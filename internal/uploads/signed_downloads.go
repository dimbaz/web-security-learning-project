package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(signingKey [32]byte, fileID int64, expiresValue, providedSignature string, now time.Time) bool {
	expires, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil {
		return false
	}
	expectedSignature := signDownload(signingKey, fileID, expires)
	decodedExpSignature, err := hex.DecodeString(expectedSignature)
	if err != nil {
		return false
	}
	decodedProvSignature, err := hex.DecodeString(providedSignature)
	if err != nil {
		return false
	}
	if expires <= now.Unix() || subtle.ConstantTimeCompare(decodedExpSignature, decodedProvSignature) != 1 {
		return false
	}
	return true
}

func signDownload(signingKey [32]byte, fileID int64, expires int64) string {
	mac := hmac.New(sha256.New, signingKey[:])
	fmt.Fprintf(mac, "GET\n/files/%d/signed-download\n%d", fileID, expires)
	signature := hex.EncodeToString(mac.Sum(nil))
	return strings.ToLower(signature)
}
