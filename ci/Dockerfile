FROM golang:1.12.5 as builder

WORKDIR /opt/app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . ./

RUN go test ./...

RUN CGO_ENABLED=0 GOOS=linux go build -a -o /app .

FROM scratch

COPY --from=builder /app ./

ENTRYPOINT ["./app"]
