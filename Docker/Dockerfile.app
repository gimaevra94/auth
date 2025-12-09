FROM golang:latest AS go
WORKDIR /src
COPY app/ .
RUN go mod download && go build -o /main && apt-get update && apt-get install -y build-essential
FROM gcr.io/distroless/base-debian12 AS app
COPY --from=go /main /app/app
WORKDIR /app
CMD ["/app/app"]