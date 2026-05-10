package auth

import (
	"context"

	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
)

type loginResult struct {
	user        *store.User
	pair        *session.TokenPair
	cookieValue string
}

func (h *Handler) completeLogin(ctx context.Context, input LoginInput) (*loginResult, error) {
	user, err := h.service.Login(ctx, input)
	if err != nil {
		return nil, err
	}
	if h.session == nil {
		return &loginResult{user: user}, nil
	}

	pair, err := h.session.IssueTokens(ctx, session.IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "goauth-web",
	})
	if err != nil {
		return nil, err
	}
	cookieValue, err := h.session.IssueOIDCAuthorizeCookie(*user, 0, pair.SessionID)
	if err != nil {
		return nil, err
	}
	return &loginResult{
		user:        user,
		pair:        pair,
		cookieValue: cookieValue,
	}, nil
}
