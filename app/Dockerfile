FROM golang:1.19.0-alpine AS builder
WORKDIR /app
COPY ["go.mod", "./"]
COPY ["go.sum", "./"]
RUN ["go", "mod", "download"]
COPY ["cmd/", "./cmd"]
ENV CGO_ENABLED=0
RUN ["go", "build", "-mod=mod", "-o", "app", "./cmd/hello"]

FROM golang:1.19.0-alpine
WORKDIR /app
COPY --from=builder /app/app ./app
ARG PORT=8080
EXPOSE ${PORT}
CMD ["./app"]