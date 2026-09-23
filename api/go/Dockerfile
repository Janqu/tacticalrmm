FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/qdt-rmm-api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/qdt-rmm-bootstrap ./cmd/bootstrap

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S qdt-rmm && adduser -S -G qdt-rmm qdt-rmm
WORKDIR /app
COPY --from=build /out/ /app/
COPY LICENSE.md /app/LICENSE.md
USER qdt-rmm
EXPOSE 8080
CMD ["/app/qdt-rmm-api"]
