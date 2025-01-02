FROM golang:latest AS go
WORKDIR /
COPY ./app/ .
RUN go mod download && go build -o /app && apt-get update && apt-get install -y build-essential
FROM gcr.io/distroless/base-debian12 AS app
COPY --from=go app /app/app
CMD ["/app/app"]