package sftp

import (
	"context"
	"encoding/binary"
	"io"
	"strings"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	dockerContainer "github.com/docker/docker/api/types/container"
	"golang.org/x/crypto/ssh"

	"github.com/pelican-dev/wings/config"
	"github.com/pelican-dev/wings/environment"
	dockerEnv "github.com/pelican-dev/wings/environment/docker"
	"github.com/pelican-dev/wings/internal/database"
	"github.com/pelican-dev/wings/internal/models"
	"github.com/pelican-dev/wings/server"
)

const PermissionTerminalSSH = "terminal.ssh"

// resizeEvent carries PTY dimension changes from SSH window-change requests.
type resizeEvent struct {
	cols uint32
	rows uint32
}

// ShellHandler handles an interactive SSH shell session by creating a Docker exec
// instance with PTY allocation inside the server's container.
type ShellHandler struct {
	mu          sync.Mutex
	srv         *server.Server
	conn        *ssh.ServerConn
	channel     ssh.Channel
	permissions []string
	logger      *log.Entry
}

// NewShellHandler creates a new SSH shell session handler.
func NewShellHandler(sc *ssh.ServerConn, srv *server.Server, channel ssh.Channel) *ShellHandler {
	uuid, _ := sc.Permissions.Extensions["user"]
	return &ShellHandler{
		srv:         srv,
		conn:        sc,
		channel:     channel,
		permissions: strings.Split(sc.Permissions.Extensions["permissions"], ","),
		logger: log.WithFields(log.Fields{
			"subsystem": "ssh-shell",
			"user":      uuid,
			"ip":        sc.RemoteAddr(),
			"server":    srv.ID(),
		}),
	}
}

// can checks if the user has the specified permission.
func (h *ShellHandler) can(permission string) bool {
	if h.srv.IsSuspended() {
		return false
	}
	for _, p := range h.permissions {
		if p == permission || p == "*" {
			return true
		}
	}
	return false
}

// logActivity logs an SSH session event to the activity database.
func (h *ShellHandler) logActivity(event models.Event, metadata map[string]interface{}) {
	a := models.Activity{
		Server:   h.srv.ID(),
		Event:    event,
		Metadata: metadata,
		IP:       h.conn.RemoteAddr().String(),
	}
	user, _ := h.conn.Permissions.Extensions["user"]
	if tx := database.Instance().Create(a.SetUser(user)); tx.Error != nil {
		h.logger.WithField("error", tx.Error).WithField("event", event).Error("ssh-shell: failed to log activity event")
	}
}

// Handle manages the full lifecycle of an SSH shell session:
//  1. Validate permissions and server state
//  2. Create a Docker exec instance with TTY
//  3. Pipe I/O between SSH channel and Docker exec
//  4. Handle PTY resize requests via resizeCh
//  5. Clean up on disconnect
func (h *ShellHandler) Handle(ctx context.Context, initialCols, initialRows uint32, termType string, resizeCh <-chan resizeEvent) error {
	// Check if shell access is globally enabled.
	if !config.Get().System.Sftp.ShellEnabled {
		h.logger.Warn("ssh-shell: shell access is disabled in Wings configuration")
		_, _ = h.channel.Write([]byte("shell access is disabled\r\n"))
		_ = h.channel.Close()
		return nil
	}

	// Check user permission.
	if !h.can(PermissionTerminalSSH) {
		h.logger.Warn("ssh-shell: user does not have terminal.ssh permission")
		_, _ = h.channel.Write([]byte("permission denied\r\n"))
		_ = h.channel.Close()
		return nil
	}

	// Verify the server is running.
	if !h.srv.IsRunning() {
		h.logger.Warn("ssh-shell: server is not running")
		_, _ = h.channel.Write([]byte("server is not running\r\n"))
		_ = h.channel.Close()
		return nil
	}

	// Get the Docker client and container ID.
	env, ok := h.srv.Environment.(*dockerEnv.Environment)
	if !ok {
		return errors.New("ssh-shell: environment is not Docker")
	}

	cli, err := environment.Docker()
	if err != nil {
		return errors.Wrap(err, "ssh-shell: failed to get Docker client")
	}

	containerID := env.Id

	shellPath := config.Get().System.Sftp.ShellPath

	// Log session start.
	h.logActivity(server.ActivitySSHSessionStart, map[string]interface{}{
		"shell": shellPath,
	})

	startTime := time.Now()
	h.logger.Info("ssh-shell: session started")

	// Register session in connection bag for tracking and cleanup.
	user, _ := h.conn.Permissions.Extensions["user"]
	shellCtx := h.srv.Shell().Context(user)
	defer h.srv.Shell().Cancel(user)

	// Build environment variables for the exec session.
	execEnv := []string{
		"TERM=" + termType,
	}

	// Create Docker exec instance with TTY.
	execConfig := dockerContainer.ExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Cmd:          []string{shellPath},
		WorkingDir:   "/home/container",
		Env:          execEnv,
	}

	execCreateResp, err := cli.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		return errors.Wrap(err, "ssh-shell: failed to create exec instance")
	}

	// Attach to the exec instance.
	execAttachResp, err := cli.ContainerExecAttach(ctx, execCreateResp.ID, dockerContainer.ExecAttachOptions{
		Tty:    true,
		Detach: false,
	})
	if err != nil {
		return errors.Wrap(err, "ssh-shell: failed to attach to exec instance")
	}
	defer execAttachResp.Close()

	// Set initial PTY size.
	if initialCols > 0 && initialRows > 0 {
		_ = cli.ContainerExecResize(ctx, execCreateResp.ID, dockerContainer.ResizeOptions{
			Height: uint(initialRows),
			Width:  uint(initialCols),
		})
	}

	// Set up context for clean shutdown derived from the shell connection bag.
	// This allows the server to cancel all shell sessions on stop.
	sessionCtx, sessionCancel := context.WithCancel(shellCtx)
	defer sessionCancel()

	var once sync.Once
	closeSession := func() {
		once.Do(sessionCancel)
	}

	// Goroutine: SSH channel stdin -> Docker exec stdin
	go func() {
		defer closeSession()
		_, _ = io.Copy(execAttachResp.Conn, h.channel)
	}()

	// Goroutine: Docker exec stdout -> SSH channel stdout
	go func() {
		defer closeSession()
		_, _ = io.Copy(h.channel, execAttachResp.Reader)
	}()

	// Goroutine: handle PTY resize events from SSH window-change requests.
	go func() {
		for ev := range resizeCh {
			_ = cli.ContainerExecResize(ctx, execCreateResp.ID, dockerContainer.ResizeOptions{
				Height: uint(ev.rows),
				Width:  uint(ev.cols),
			})
		}
	}()

	// Wait for session to end (context cancelled by either goroutine).
	<-sessionCtx.Done()

	// Log session end.
	duration := time.Since(startTime)
	h.logActivity(server.ActivitySSHSessionEnd, map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
	})
	h.logger.WithField("duration", duration).Info("ssh-shell: session ended")

	return nil
}

// parsePtyRequest parses the SSH "pty-req" payload.
// Format per RFC 4254:
//
//	string   TERM environment variable value (e.g., "xterm-256color")
//	uint32   terminal width, columns
//	uint32   terminal height, rows
//	uint32   terminal width, pixels
//	uint32   terminal height, pixels
//	string   encoded terminal modes
func parsePtyRequest(payload []byte) (term string, cols, rows uint32) {
	if len(payload) < 4 {
		return "xterm", 80, 24
	}
	// Read the TERM string (length-prefixed).
	termLen := binary.BigEndian.Uint32(payload[0:4])
	offset := 4 + int(termLen)
	if len(payload) < offset+8 {
		return "xterm", 80, 24
	}
	term = string(payload[4 : 4+termLen])
	if term == "" {
		term = "xterm"
	}
	cols = binary.BigEndian.Uint32(payload[offset : offset+4])
	rows = binary.BigEndian.Uint32(payload[offset+4 : offset+8])
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	return
}

// parseWindowChange parses a "window-change" request payload.
// Format per RFC 4254:
//
//	uint32   terminal width, columns
//	uint32   terminal height, rows
//	uint32   terminal width, pixels
//	uint32   terminal height, pixels
func parseWindowChange(payload []byte) (cols, rows uint32) {
	if len(payload) < 8 {
		return 80, 24
	}
	cols = binary.BigEndian.Uint32(payload[0:4])
	rows = binary.BigEndian.Uint32(payload[4:8])
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	return
}

// HandleExec runs a single command inside the server's container using Docker exec
// without TTY. This is used by VS Code Remote SSH and similar tools that send
// "exec" requests instead of interactive "shell" sessions.
func (h *ShellHandler) HandleExec(ctx context.Context, cmd string) error {
	// Check if shell access is globally enabled.
	if !config.Get().System.Sftp.ShellEnabled {
		_, _ = h.channel.Write([]byte("shell access is disabled\r\n"))
		_ = h.channel.Close()
		return nil
	}

	// Check user permission.
	if !h.can(PermissionTerminalSSH) {
		_, _ = h.channel.Write([]byte("permission denied\r\n"))
		_ = h.channel.Close()
		return nil
	}

	// Verify the server is running.
	if !h.srv.IsRunning() {
		_, _ = h.channel.Write([]byte("server is not running\r\n"))
		_ = h.channel.Close()
		return nil
	}

	env, ok := h.srv.Environment.(*dockerEnv.Environment)
	if !ok {
		return errors.New("ssh-exec: environment is not Docker")
	}

	cli, err := environment.Docker()
	if err != nil {
		return errors.Wrap(err, "ssh-exec: failed to get Docker client")
	}

	containerID := env.Id

	h.logActivity(server.ActivitySSHSessionStart, map[string]interface{}{
		"exec": cmd,
	})

	startTime := time.Now()
	h.logger.WithField("cmd", cmd).Info("ssh-exec: running command")

	// Use bash -c to support pipes, redirects, etc.
	execConfig := dockerContainer.ExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Cmd:          []string{"/bin/bash", "-c", cmd},
		WorkingDir:   "/home/container",
	}

	execCreateResp, err := cli.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		return errors.Wrap(err, "ssh-exec: failed to create exec instance")
	}

	execAttachResp, err := cli.ContainerExecAttach(ctx, execCreateResp.ID, dockerContainer.ExecAttachOptions{
		Tty:    false,
		Detach: false,
	})
	if err != nil {
		return errors.Wrap(err, "ssh-exec: failed to attach to exec instance")
	}
	defer execAttachResp.Close()

	// Pipe I/O between SSH channel and Docker exec.
	stdoutDone := make(chan struct{})
	stdinDone := make(chan struct{})

	// Docker exec stdout/stderr -> SSH channel
	go func() {
		defer close(stdoutDone)
		io.Copy(h.channel, execAttachResp.Reader)
	}()

	// SSH channel stdin -> Docker exec stdin
	go func() {
		defer close(stdinDone)
		io.Copy(execAttachResp.Conn, h.channel)
	}()

	// Wait for stdout to finish (command completed)
	<-stdoutDone

	// Close docker exec stdin to signal we're done
	execAttachResp.Close()

	// Inspect the exec to get the exit code
	var exitCode int
	inspectResp, err := cli.ContainerExecInspect(ctx, execCreateResp.ID)
	if err != nil {
		h.logger.WithField("error", err).Warn("ssh-exec: failed to inspect exec for exit code")
		exitCode = 0
	} else {
		exitCode = inspectResp.ExitCode
	}

	// Send exit status to the SSH client (required by VS Code Remote SSH)
	_, _ = h.channel.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{ExitStatus: uint32(exitCode)}))
	_ = h.channel.Close()

	duration := time.Since(startTime)
	h.logActivity(server.ActivitySSHSessionEnd, map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"exec":        cmd,
	})
	h.logger.WithField("duration", duration).WithField("cmd", cmd).WithField("exit_code", exitCode).Info("ssh-exec: command completed")

	return nil
}
