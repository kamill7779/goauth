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
	twoFactor   *loginTwoFactorChallenge
}

func (h *Handler) completeLogin(ctx context.Context, input LoginInput) (*loginResult, error) {
	user, err := h.service.Login(ctx, input)
	if err != nil {
		return nil, err
	}
	challenge, err := h.startLoginTwoFactorChallengeIfRequired(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if challenge != nil {
		return &loginResult{user: user, twoFactor: challenge}, nil
	}

	pair, cookieValue, err := h.issueLoginTokens(ctx, user)
	if err != nil {
		return nil, err
	}
	return &loginResult{
		user:        user,
		pair:        pair,
		cookieValue: cookieValue,
	}, nil
}

func (h *Handler) issueLoginTokens(ctx context.Context, user *store.User) (*session.TokenPair, string, error) {
	if h.session == nil {
		return nil, "", nil
	}
	pair, err := h.session.IssueTokens(ctx, session.IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "goauth-web",
	})
	if err != nil {
		return nil, "", err
	}
	cookieValue, err := h.session.IssueOIDCAuthorizeCookie(*user, 0, pair.SessionID)
	if err != nil {
		return nil, "", err
	}
	return pair, cookieValue, nil
}
