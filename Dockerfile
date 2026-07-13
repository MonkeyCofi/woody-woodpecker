FROM alpine:3.23.5

RUN apk update && apk add gcc && apk add zsh && apk add musl-dev

WORKDIR /src

