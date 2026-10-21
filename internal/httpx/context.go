package httpx

import (
	"context"
	"uuid"
)

type contextKey string

const cspNonceContextKey contextKey = "csp-nonce"
const requestUUID contextKey = "requestID"

func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, cspNonceContextKey, nonce)
}

func CSPNonce(ctx context.Context) string {
	nonce, _ := ctx.Value(cspNonceContextKey).(string)
	return nonce
}

func WithRequestID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, requestUUID, id)
}

func RequestIdFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(requestUUID).(uuid.UUID)
	return id, ok
}
