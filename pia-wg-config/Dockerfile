FROM golang:alpine AS build
RUN go install github.com/kylegrantlucas/pia-wg-config@latest

FROM alpine:latest
RUN apk add --no-cache ca-certificates wireguard-tools
COPY --from=build /go/bin/pia-wg-config /usr/local/bin/pia-wg-config
ENTRYPOINT ["pia-wg-config"]
