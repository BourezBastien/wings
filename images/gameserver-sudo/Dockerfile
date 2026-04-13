FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install useful tools + sudo + runtime dependencies for game servers
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    unzip \
    tar \
    zip \
    sudo \
    iproute2 \
    tini \
    locales \
    tzdata \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Configure locale
RUN update-locale lang=en_US.UTF-8 \
    && dpkg-reconfigure --frontend noninteractive locales

# Create container user with bash shell (UID/GID set by Wings via passwd mount)
RUN useradd -m -d /home/container -s /bin/bash container \
    && ln -s /home/container/ /nonexistent \
    && echo "container ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/container \
    && chmod 0440 /etc/sudoers.d/container

ENV USER=container HOME=/home/container

WORKDIR /home/container

STOPSIGNAL SIGINT

COPY --chown=container:container ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/entrypoint.sh"]
