FROM golang:1.24.2-alpine3.21 AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/main

FROM alpine:3.21

RUN apk --no-cache add ca-certificates tzdata

ENV TZ=Europe/Moscow

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/templateshtml ./templateshtml

RUN mkdir -p /app/uploads

EXPOSE 8080

CMD ["./main"]