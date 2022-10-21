FROM golang:1.18-alpine


WORKDIR /app

COPY .env ./
COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN go build -o /server

EXPOSE 8000

CMD ["/server"]