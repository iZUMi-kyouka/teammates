FROM alpine:latest
RUN apk add --no-cache bash curl

COPY ./crontab /etc/crontabs/root

CMD ["crond", "-f", "-d", "8"]
