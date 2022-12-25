FROM golang:1.19-alpine as build

WORKDIR /app
COPY *.go go.mod go.sum /app

# CGO is disabled to simplify the build and because we use pure Go.
# For more info: https://dave.cheney.net/tag/cgo
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o sysdig_secure_exporter .

# A multi-stage build keeps the image size down and cleans up un-needed artifacts.
# For more info: https://docs.docker.com/build/building/multi-stage/
FROM alpine:3.17

RUN apk update

WORKDIR /app
COPY --from=build /app /app

# Make sure to change the port to match the 'web.listen-address' flag.
EXPOSE 9100

ENTRYPOINT ["./sysdig_secure_exporter"]