FROM alpine:3.20

RUN apk add --no-cache bash curl jq

WORKDIR /app

COPY sync-index-patterns.sh /app/sync-index-patterns.sh

RUN chmod +x /app/sync-index-patterns.sh

CMD ["/app/sync-index-patterns.sh"]
