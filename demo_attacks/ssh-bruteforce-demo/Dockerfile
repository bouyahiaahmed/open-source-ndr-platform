FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    openssh-client \
    sshpass \
    python3 \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY run_ssh_bruteforce_demo.sh /app/run_ssh_bruteforce_demo.sh
RUN chmod +x /app/run_ssh_bruteforce_demo.sh

ENTRYPOINT ["/app/run_ssh_bruteforce_demo.sh"]
