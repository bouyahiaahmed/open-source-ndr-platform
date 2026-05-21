FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    nmap \
    python3 \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY run_nmap_demo.sh /app/run_nmap_demo.sh
RUN chmod +x /app/run_nmap_demo.sh

ENTRYPOINT ["/app/run_nmap_demo.sh"]
