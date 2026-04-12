FROM debian:bookworm-slim

# Install minimal useful tools + sudo in one layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    unzip \
    git \
    sudo \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create container user with bash shell (UID/GID set by Wings via passwd mount)
RUN useradd -m -s /bin/bash container \
    && echo "container ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/container \
    && chmod 0440 /etc/sudoers.d/container

USER container
WORKDIR /home/container
CMD ["/bin/bash"]
