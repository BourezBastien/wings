package server

import (
	"github.com/pelican-dev/wings/system"
)

// Sftp returns the SFTP connection bag for the server instance. This bag tracks
// all open SFTP connections by individual user and allows for a single user or
// all users to be disconnected by other processes.
func (s *Server) Sftp() *system.ContextBag {
	s.Lock()
	defer s.Unlock()

	if s.sftpBag == nil {
		s.sftpBag = system.NewContextBag(s.Context())
	}

	return s.sftpBag
}

// Shell returns the SSH shell connection bag for the server instance. This bag tracks
// all open SSH shell sessions by individual user and allows for a single user or
// all users to be disconnected by other processes.
func (s *Server) Shell() *system.ContextBag {
	s.Lock()
	defer s.Unlock()

	if s.shellBag == nil {
		s.shellBag = system.NewContextBag(s.Context())
	}

	return s.shellBag
}
