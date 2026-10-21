package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
	MaxSafeIntegerFloat float64        = (1 << 53) - 1
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey, expectedKey []byte, payload any) WebhookVerification {
	if len(providedKey) != len(expectedKey) || subtle.ConstantTimeCompare(providedKey, expectedKey) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized, OrderID: 0}
	}
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed, OrderID: 0}
	}
	status, ok := payloadRecord["status"].(string)
	if !ok || status != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed, OrderID: 0}
	}
	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok || math.Trunc(orderID) != orderID || orderID <= 0 || orderID > MaxSafeIntegerFloat {
		return WebhookVerification{Outcome: WebhookMalformed, OrderID: 0}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
