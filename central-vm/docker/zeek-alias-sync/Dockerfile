FROM alpine:3.20

RUN apk add --no-cache bash curl jq

WORKDIR /app

COPY sync-aliases.sh /app/sync-aliases.sh

RUN chmod +x /app/sync-aliases.sh

CMD ["/app/sync-aliases.sh"]
