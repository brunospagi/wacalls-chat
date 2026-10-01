package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const segredoTeste = "segredo-de-teste-com-mais-de-32-caracteres"

func novoServidorRevenda(t *testing.T) *server {
	t.Helper()
	t.Setenv("WACALLS_REVENDA_SEGREDO", segredoTeste)
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "revenda.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	auth, err := newAuthStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return &server{auth: auth, db: db, sessions: newTestManager(t)}
}

func pedidoAssinado(t *testing.T, corpo any, tempo time.Time) *http.Request {
	t.Helper()
	b, _ := json.Marshal(corpo)
	seg := strconv.FormatInt(tempo.Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, "/api/revenda/provisionar", bytes.NewReader(b))
	req.Header.Set("X-Revenda-Tempo", seg)
	req.Header.Set("X-Revenda-Assinatura", revendaAssinar(append([]byte(seg+"."), b...)))
	return req
}

func provisionar(t *testing.T, s *server, usuarios []revendaPedidoUsuario) map[string]any {
	t.Helper()
	pedido := map[string]any{
		"empresa":  map[string]string{"email": "loja-7@atendimento.revenda", "nome": "Minha Revenda"},
		"usuarios": usuarios,
	}
	rec := httptest.NewRecorder()
	s.handleRevendaProvisionar(rec, pedidoAssinado(t, pedido, time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("provisionar: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp
}

func TestProvisionarIdempotenteEDesativaQuemSaiu(t *testing.T) {
	s := novoServidorRevenda(t)
	ctx := context.Background()
	ana := revendaPedidoUsuario{Email: "u1.l7@atendimento.revenda", Nome: "Ana", Admin: true, Ativo: true}
	beto := revendaPedidoUsuario{Email: "u2.l7@atendimento.revenda", Nome: "Beto", Ativo: true}

	primeira := provisionar(t, s, []revendaPedidoUsuario{ana, beto})
	segunda := provisionar(t, s, []revendaPedidoUsuario{ana, beto})
	if primeira["empresaId"] != segunda["empresaId"] {
		t.Fatal("a empresa foi criada duas vezes")
	}
	empresa := primeira["empresaId"].(string)
	for _, email := range []string{ana.Email, beto.Email} {
		_, dono, ativo, err := s.revendaUsuario(ctx, email)
		if err != nil || dono != empresa || !ativo {
			t.Fatalf("%s: dono=%q ativo=%v err=%v", email, dono, ativo, err)
		}
	}
	if ok, _ := s.auth.HasRole(ctx, primeira["usuarios"].(map[string]any)[ana.Email].(string), RoleAdmin); !ok {
		t.Fatal("Ana deveria ser admin da empresa")
	}

	provisionar(t, s, []revendaPedidoUsuario{ana}) // Beto saiu da loja
	if _, _, ativo, _ := s.revendaUsuario(ctx, beto.Email); ativo {
		t.Fatal("quem saiu da lista deve perder o acesso")
	}
}

func TestProvisionarExigeAssinaturaValidaERecente(t *testing.T) {
	s := novoServidorRevenda(t)
	pedido := map[string]any{"empresa": map[string]string{"email": "x@y.z", "nome": "X"}}

	rec := httptest.NewRecorder()
	s.handleRevendaProvisionar(rec, pedidoAssinado(t, pedido, time.Now().Add(-10*time.Minute)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("pedido antigo aceito: %d", rec.Code)
	}
	req := pedidoAssinado(t, pedido, time.Now())
	req.Header.Set("X-Revenda-Assinatura", strings.Repeat("0", 64))
	rec = httptest.NewRecorder()
	s.handleRevendaProvisionar(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("assinatura falsa aceita: %d", rec.Code)
	}

	t.Setenv("WACALLS_REVENDA_SEGREDO", "") // sem segredo, a integração não existe
	rec = httptest.NewRecorder()
	s.handleRevendaProvisionar(rec, pedidoAssinado(t, pedido, time.Now()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("sem segredo deveria responder 404: %d", rec.Code)
	}
}

func tokenSSO(email, nonce string, exp time.Time) string {
	b, _ := json.Marshal(revendaSSOPayload{Email: email, Exp: exp.Unix(), Nonce: nonce})
	p := base64.RawURLEncoding.EncodeToString(b)
	return p + "." + revendaAssinar([]byte("sso."+p))
}

func TestSSOEntraUmaVezSo(t *testing.T) {
	s := novoServidorRevenda(t)
	provisionar(t, s, []revendaPedidoUsuario{{Email: "u1.l7@atendimento.revenda", Nome: "Ana", Ativo: true}})
	t.Setenv("WACALLS_REVENDA_SEGREDO", segredoTeste)

	entrar := func(token string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleRevendaSSO(rec, httptest.NewRequest(http.MethodGet, "/sso?t="+token, nil))
		return rec
	}
	token := tokenSSO("u1.l7@atendimento.revenda", "n-1", time.Now().Add(time.Minute))
	rec := entrar(token)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/chats" {
		t.Fatalf("login único falhou: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), authCookieName+"=") {
		t.Fatal("sem cookie de sessão")
	}
	if entrar(token).Code != http.StatusForbidden {
		t.Fatal("o mesmo token não pode ser usado duas vezes")
	}
	if entrar(tokenSSO("u1.l7@atendimento.revenda", "n-2", time.Now().Add(-time.Second))).Code != http.StatusForbidden {
		t.Fatal("token vencido aceito")
	}
	if entrar(tokenSSO("u1.l7@atendimento.revenda", "n-3", time.Now().Add(time.Hour))).Code != http.StatusForbidden {
		t.Fatal("validade longa demais aceita")
	}
	if entrar(tokenSSO("ninguem@atendimento.revenda", "n-4", time.Now().Add(time.Minute))).Code != http.StatusForbidden {
		t.Fatal("usuário inexistente entrou")
	}
	adulterado := strings.Replace(tokenSSO("u1.l7@atendimento.revenda", "n-5", time.Now().Add(time.Minute)), ".", ".0", 1)
	if entrar(adulterado).Code != http.StatusForbidden {
		t.Fatal("assinatura adulterada aceita")
	}
}

func TestFrameAncestorsSoComConfiguracao(t *testing.T) {
	h := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("sem configuração, continua proibido embutir")
	}
	t.Setenv("WACALLS_FRAME_ANCESTORS", "https://painel.exemplo.com.br")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("Content-Security-Policy") != "frame-ancestors https://painel.exemplo.com.br" ||
		rec.Header().Get("X-Frame-Options") != "" {
		t.Fatalf("cabeçalhos: %v", rec.Header())
	}
}
