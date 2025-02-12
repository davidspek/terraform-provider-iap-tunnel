package iap_tunnel

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type OAuthTokenProvider struct {
	ts           oauth2.TokenSource
	currentToken *oauth2.Token
	mu           sync.RWMutex
}

func NewOAuthTokenProvider(ts oauth2.TokenSource) TokenProvider {
	return &OAuthTokenProvider{
		ts: ts,
	}
}

func (p *OAuthTokenProvider) GetHeaders() (http.Header, error) {
	p.mu.RLock()
	token := p.currentToken
	p.mu.RUnlock()

	if token == nil || token.Expiry.Before(time.Now()) {
		var err error
		token, err = p.ts.Token()
		if err != nil {
			return nil, fmt.Errorf("failed to get token: %w", err)
		}
		p.mu.Lock()
		p.currentToken = token
		p.mu.Unlock()
	}

	return http.Header{
		"Origin":        []string{TUNNEL_CLOUDPROXY_ORIGIN},
		"User-Agent":    []string{TUNNEL_USER_AGENT},
		"Authorization": []string{fmt.Sprintf("Bearer %s", token.AccessToken)},
	}, nil
}

func (p *OAuthTokenProvider) RefreshToken(ctx context.Context) error {
	token, err := p.ts.Token()
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	p.mu.Lock()
	p.currentToken = token
	p.mu.Unlock()

	return nil
}
