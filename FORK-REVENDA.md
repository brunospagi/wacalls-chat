# Fork para o sistema Revenda

Branch `revenda` de [raphaelbat/wacalls-chat](https://github.com/raphaelbat/wacalls-chat) (MIT). O atendimento
WhatsApp de cada loja roda aqui; o Revenda cria as empresas e os usuários e faz o login único.

## O que muda em relação ao original

Código novo em `cmd/server/revenda.go` (+ `revenda_test.go`); no original, só três ganchos marcados com
`// fork revenda` (`httpapi.go`, `messageapi.go`).

| Recurso | Como funciona |
|---|---|
| Provisionamento | `POST /api/revenda/provisionar` assinado (HMAC-SHA256): cria/atualiza a empresa da loja e os usuários; quem sai da lista é desativado. Idempotente |
| Login único | `GET /sso?t=…` assinado, válido por até 2 min e uma única vez; abre direto a conversa quando recebe um telefone |
| Webhook | cada mensagem recebida (não de grupo, até 10 min) vai assinada para `WACALLS_REVENDA_WEBHOOK`, com 3 tentativas |
| Embutir no painel | `WACALLS_FRAME_ANCESTORS` troca o `X-Frame-Options: DENY` por `frame-ancestors <painel>` |
| Tela de login | sem e-mail padrão preenchido e sem linha de patrocínio (créditos no LICENSE) |
| Docker | `Dockerfile` com dados em `/dados` (volume), sem administrador padrão, sem root |

## Variáveis

| Variável | Uso |
|---|---|
| `WACALLS_REVENDA_SEGREDO` | segredo compartilhado (≥ 32 caracteres). Sem ele, as rotas do Revenda não existem |
| `WACALLS_REVENDA_WEBHOOK` | URL do Revenda para os eventos |
| `WACALLS_FRAME_ANCESTORS` | origem do painel que pode embutir a tela |
| `WACALLS_MAX_SESSOES` | acessos simultâneos por usuário (sugestão: 3) |

## Atualizar com o original

```bash
git fetch upstream && git checkout revenda && git merge upstream/main
go test ./... && docker build -t wacalls-revenda .
```
