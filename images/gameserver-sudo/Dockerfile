FROM ghcr.io/parkervcp/yolks:debian

# Install useful tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    unzip \
    git \
    bash \
    sudo \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Configure passwordless sudo for the container user
RUN echo "container ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/container \
    && chmod 0440 /etc/sudoers.d/container

# Set bash as default shell
RUN chsh -s /bin/bash container 2>/dev/null || true

CMD ["/bin/bash"]
