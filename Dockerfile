# Imagem do atendimento (fork revenda). Dados (banco, mídias, gravações) ficam em /dados — use um volume.
#   docker build -t wacalls-revenda .
FROM node:22-alpine AS cliente
WORKDIR /src/client
COPY client/package.json client/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY client/ ./
RUN npm run build    # gera /src/dist

FROM golang:1.27-alpine AS servidor
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /wacalls ./cmd/server

FROM alpine:3.22
# ffmpeg: conversão de áudio (mensagens de voz, música de espera)
RUN apk add --no-cache ca-certificates tzdata ffmpeg \
    && adduser -D -u 1000 wacalls && mkdir /dados && chown wacalls /dados
ENV TZ=America/Sao_Paulo WACALLS_WELCOME=off
COPY --from=servidor /wacalls /app/wacalls
COPY --from=cliente /src/dist /app/dist
USER wacalls
WORKDIR /dados
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8080/api/revenda/saude >/dev/null || exit 1
# sem administrador padrão: as empresas e os usuários vêm do Revenda (/api/revenda/provisionar)
ENTRYPOINT ["/app/wacalls", "-addr", ":8080", "-db", "/dados/wacalls.db", "-static", "/app/dist", "-seed-admin-email", ""]
