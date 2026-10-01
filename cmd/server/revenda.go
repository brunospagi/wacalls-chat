package main

// Integração com o sistema Revenda (fork brunospagi/wacalls-chat, branch "revenda").
//
// Tudo o que o fork acrescenta fica neste arquivo. No código original há só três ganchos:
// registro das rotas (httpapi.go), aviso de mensagem recebida (messageapi.go) e o cabeçalho
// frame-ancestors (httpapi.go). Assim as atualizações do projeto original entram com poucos conflitos.
//
// Variáveis de ambiente:
//
//	WACALLS_REVENDA_SEGREDO   segredo compartilhado com o Revenda (HMAC-SHA256). Sem ele, as rotas
//	                          /sso e /api/revenda/* respondem 404 e nenhum webhook é enviado.
//	WACALLS_REVENDA_WEBHOOK   URL do Revenda que recebe os eventos (mensagem recebida).
//	WACALLS_FRAME_ANCESTORS   origens que podem embutir a tela (ex.: https://painel.seudominio.com.br).
//
// Assinatura das chamadas servidor a servidor (nos dois sentidos):
//
//	X-Revenda-Tempo:       segundos Unix
//	X-Revenda-Assinatura:  hex(HMAC-SHA256(segredo, tempo + "." + corpo))   — validade de 5 minutos
//
// Login único: GET /sso?t=<payload base64url>.<hex(HMAC-SHA256(segredo, "sso." + payload))>, com
// payload {"email", "exp", "nonce", "telefone"?}; vale até exp (máx. 2 min) e uma única vez.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow/types"
)

const (
	revendaTolerancia   = 5 * time.Minute
	revendaSSOValidade  = 2 * time.Minute
	revendaMensagemNova = 10 * time.Minute // mensagens mais antigas (sincronização de histórico) não viram aviso
	revendaTextoMax     = 1000
)

func revendaSegredo() []byte {
	return []byte(strings.TrimSpace(os.Getenv("WACALLS_REVENDA_SEGREDO")))
}

func revendaAtivo() bool { return len(revendaSegredo()) >= 32 }

func revendaFrameAncestors() string {
	return strings.TrimSpace(os.Getenv("WACALLS_FRAME_ANCESTORS"))
}

func revendaAssinar(mensagem []byte) string {
	mac := hmac.New(sha256.New, revendaSegredo())
	mac.Write(mensagem)
	return hex.EncodeToString(mac.Sum(nil))
}

func revendaConfere(mensagem []byte, assinatura string) bool {
	esperada, err := hex.DecodeString(revendaAssinar(mensagem))
	recebida, err2 := hex.DecodeString(strings.TrimSpace(assinatura))
	return err == nil && err2 == nil && hmac.Equal(esperada, recebida)
}

// revendaLerAssinado lê o corpo e confere tempo + assinatura. Erro = 401 sem detalhes.
func revendaLerAssinado(r *http.Request) ([]byte, error) {
	corpo, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	tempo := r.Header.Get("X-Revenda-Tempo")
	seg, err := strconv.ParseInt(tempo, 10, 64)
	if err != nil {
		return nil, errors.New("tempo invalido")
	}
	if d := time.Since(time.Unix(seg, 0)); d > revendaTolerancia || d < -revendaTolerancia {
		return nil, errors.New("tempo fora da janela")
	}
	if !revendaConfere(append([]byte(tempo+"."), corpo...), r.Header.Get("X-Revenda-Assinatura")) {
		return nil, errors.New("assinatura invalida")
	}
	return corpo, nil
}

func (s *server) registerRevendaRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /sso", s.handleRevendaSSO)
	mux.HandleFunc("POST /api/revenda/provisionar", s.handleRevendaProvisionar)
	mux.HandleFunc("GET /api/revenda/saude", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "integracao": revendaAtivo()})
	})
}

// ---------------------------------------------------------------- usuários

func (s *server) revendaUsuario(ctx context.Context, email string) (id, parent string, ativo bool, err error) {
	var a int
	err = s.db.QueryRowContext(ctx, `SELECT id, COALESCE(parent_id, ''), active FROM users WHERE email = ?`,
		normalizeEmail(email)).Scan(&id, &parent, &a)
	return id, parent, a == 1, err
}

func revendaSenhaAleatoria() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) // ninguém usa: o acesso é sempre pelo login único
}

type revendaPedidoUsuario struct {
	Email string `json:"email"`
	Nome  string `json:"nome"`
	Admin bool   `json:"admin"`
	Ativo bool   `json:"ativo"`
}

type revendaPedido struct {
	Empresa struct {
		Email string `json:"email"`
		Nome  string `json:"nome"`
	} `json:"empresa"`
	Usuarios []revendaPedidoUsuario `json:"usuarios"`
}

// handleRevendaProvisionar cria/atualiza a empresa (tenant) de uma loja e os usuários dela.
// Idempotente: o Revenda manda sempre a lista completa; quem saiu da lista é desativado.
func (s *server) handleRevendaProvisionar(w http.ResponseWriter, r *http.Request) {
	if !revendaAtivo() {
		http.NotFound(w, r)
		return
	}
	corpo, err := revendaLerAssinado(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var p revendaPedido
	if err := json.Unmarshal(corpo, &p); err != nil || !validEmail(p.Empresa.Email) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pedido invalido"})
		return
	}
	ctx := r.Context()
	nomeEmpresa := strings.TrimSpace(p.Empresa.Nome)

	raiz, parent, _, err := s.revendaUsuario(ctx, p.Empresa.Email)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		u, cerr := s.auth.AdminCreateUser(ctx, p.Empresa.Email, revendaSenhaAleatoria(), nomeEmpresa, "", RoleAdmin, "")
		if cerr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": cerr.Error()})
			return
		}
		raiz = u.ID
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	case parent != "":
		writeJSON(w, http.StatusConflict, map[string]string{"error": "e-mail da empresa pertence a outro usuario"})
		return
	}
	_ = s.auth.SetDisplayName(ctx, raiz, nomeEmpresa)

	ids := map[string]string{}
	var erros []string
	for _, u := range p.Usuarios {
		email := normalizeEmail(u.Email)
		if !validEmail(email) {
			erros = append(erros, "e-mail invalido: "+u.Email)
			continue
		}
		papel := RoleUser
		if u.Admin {
			papel = RoleAdmin
		}
		id, dono, _, err := s.revendaUsuario(ctx, email)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			novo, cerr := s.auth.AdminCreateUser(ctx, email, revendaSenhaAleatoria(), nomeEmpresa, "", papel, raiz)
			if cerr != nil {
				erros = append(erros, email+": "+cerr.Error())
				continue
			}
			id = novo.ID
		case err != nil:
			erros = append(erros, email+": "+err.Error())
			continue
		case dono != raiz:
			erros = append(erros, email+": pertence a outra empresa")
			continue
		}
		_ = s.auth.SetDisplayName(ctx, id, u.Nome)
		_ = s.auth.SetRole(ctx, id, RoleAdmin, u.Admin)
		_ = s.auth.SetActive(ctx, id, u.Ativo)
		ids[email] = id
	}
	// quem não veio na lista (removido ou desativado no Revenda) perde o acesso
	if atuais, err := s.auth.ListUsersByTenant(ctx, raiz); err == nil {
		for _, u := range atuais {
			if _, ok := ids[normalizeEmail(u.Email)]; !ok && u.ID != raiz && u.Active {
				_ = s.auth.SetActive(ctx, u.ID, false)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"empresaId": raiz, "usuarios": ids, "erros": erros})
}

// ---------------------------------------------------------------- login único

var revendaNonces = struct {
	sync.Mutex
	usados map[string]time.Time
}{usados: map[string]time.Time{}}

func revendaNonceNovo(nonce string, ate time.Time) bool {
	revendaNonces.Lock()
	defer revendaNonces.Unlock()
	agora := time.Now()
	for n, exp := range revendaNonces.usados {
		if exp.Before(agora) {
			delete(revendaNonces.usados, n)
		}
	}
	if _, usado := revendaNonces.usados[nonce]; usado || nonce == "" {
		return false
	}
	revendaNonces.usados[nonce] = ate
	return true
}

type revendaSSOPayload struct {
	Email    string `json:"email"`
	Exp      int64  `json:"exp"`
	Nonce    string `json:"nonce"`
	Telefone string `json:"telefone,omitempty"`
}

func (s *server) handleRevendaSSO(w http.ResponseWriter, r *http.Request) {
	if !revendaAtivo() {
		http.NotFound(w, r)
		return
	}
	negado := func() { http.Error(w, "Acesso expirado. Volte ao painel e abra o Atendimento de novo.", http.StatusForbidden) }
	partes := strings.SplitN(r.URL.Query().Get("t"), ".", 2)
	if len(partes) != 2 || !revendaConfere([]byte("sso."+partes[0]), partes[1]) {
		negado()
		return
	}
	bruto, err := base64.RawURLEncoding.DecodeString(partes[0])
	var p revendaSSOPayload
	if err != nil || json.Unmarshal(bruto, &p) != nil {
		negado()
		return
	}
	exp := time.Unix(p.Exp, 0)
	if time.Now().After(exp) || time.Until(exp) > revendaSSOValidade || !revendaNonceNovo(p.Nonce, exp) {
		negado()
		return
	}
	id, _, ativo, err := s.revendaUsuario(r.Context(), p.Email)
	if err != nil || !ativo {
		negado()
		return
	}
	// mesmo navegador já logado como este usuário: reaproveita a sessão (não derruba outras abas)
	if atual := s.resolveUser(r); atual == nil || atual.ID != id {
		token, err := s.auth.IssueToken(r.Context(), id)
		if err != nil {
			http.Error(w, "erro ao entrar", http.StatusInternalServerError)
			return
		}
		s.auth.MarcarAcesso(r.Context(), token, r.UserAgent(), clientIP(r))
		setAuthCookie(w, r, token)
	}
	http.Redirect(w, r, s.revendaDestino(r.Context(), id, p.Telefone), http.StatusFound)
}

// revendaDestino abre direto a conversa com o telefone, na primeira conexão pareada da empresa.
func (s *server) revendaDestino(ctx context.Context, usuarioID, telefone string) string {
	digitos := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, telefone)
	if len(digitos) < 10 {
		return "/chats"
	}
	empresa := usuarioID
	if pai, _ := s.auth.ParentOf(ctx, usuarioID); pai != "" {
		empresa = pai
	}
	for _, info := range s.sessions.infos() {
		if info.Paired && s.sessions.tenantOf(info.ID) == empresa {
			q := url.Values{"sid": {info.ID}, "jid": {digitos + "@" + types.DefaultUserServer}}
			return "/chats?" + q.Encode()
		}
	}
	return "/chats"
}

// ---------------------------------------------------------------- webhook

var revendaHTTP = &http.Client{Timeout: 10 * time.Second}

// revendaNotificarMensagem avisa o Revenda de cada mensagem recebida (não de grupos) — o Revenda
// cria o lead e liga à pessoa pelo telefone. Assíncrono, com 3 tentativas.
func revendaNotificarMensagem(sess *Session, row MessageRow, nome string, quando time.Time, grupo bool) {
	destino := strings.TrimSpace(os.Getenv("WACALLS_REVENDA_WEBHOOK"))
	if destino == "" || !revendaAtivo() || row.FromMe || grupo || time.Since(quando) > revendaMensagemNova {
		return
	}
	texto := row.Body
	if len([]rune(texto)) > revendaTextoMax {
		texto = string([]rune(texto)[:revendaTextoMax])
	}
	evento := map[string]any{
		"evento":     "mensagem_recebida",
		"empresaId":  sess.mgr.tenantOf(sess.id),
		"sessaoId":   sess.id,
		"chatJid":    row.ChatJID,
		"telefone":   revendaTelefone(sess, row.ChatJID),
		"nome":       nome,
		"tipo":       row.Kind,
		"texto":      texto,
		"mensagemId": row.ID,
		"ts":         row.Ts,
	}
	go revendaEnviar(destino, evento, sess)
}

func revendaTelefone(sess *Session, chatJID string) string {
	jid, err := types.ParseJID(chatJID)
	if err != nil {
		return ""
	}
	if jid.Server != types.HiddenUserServer {
		return jid.User
	}
	if sess.client == nil || sess.client.Store == nil || sess.client.Store.LIDs == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if pn, err := sess.client.Store.LIDs.GetPNForLID(ctx, jid); err == nil && !pn.IsEmpty() {
		return pn.User
	}
	return ""
}

func revendaEnviar(destino string, evento map[string]any, sess *Session) {
	corpo, _ := json.Marshal(evento)
	espera := time.Second
	for tentativa := 1; tentativa <= 3; tentativa++ {
		tempo := strconv.FormatInt(time.Now().Unix(), 10)
		req, err := http.NewRequest(http.MethodPost, destino, bytes.NewReader(corpo))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Revenda-Tempo", tempo)
		req.Header.Set("X-Revenda-Assinatura", revendaAssinar(append([]byte(tempo+"."), corpo...)))
		resp, err := revendaHTTP.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		sess.log.Warn("revenda webhook falhou", "tentativa", tentativa, "err", err)
		time.Sleep(espera)
		espera *= 5
	}
}
