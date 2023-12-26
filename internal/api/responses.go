package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/polygonid/sh-id-platform/internal/common"
	"github.com/polygonid/sh-id-platform/internal/core/domain"
)

// CustomQrContentResponse is a wrapper to return any content as an api response.
// Just implement the Visit* method to satisfy the expected interface for that type of response.
type CustomQrContentResponse struct {
	content []byte
}

// NewQrContentResponse returns a new CustomQrContentResponse.
func NewQrContentResponse(response []byte) *CustomQrContentResponse {
	return &CustomQrContentResponse{content: response}
}

// VisitGetQrFromStoreResponse satisfies the AuthQRCodeResponseObject
func (response CustomQrContentResponse) VisitGetQrFromStoreResponse(w http.ResponseWriter) error {
	return response.visit(w)
}

func (response CustomQrContentResponse) visit(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(response.content) // Returning the content without encoding it. It was previously encoded
	return err
}

func CredentialResponse(w3c *verifiable.W3CCredential, credential *domain.Claim) Credential {
	var expiresAt *TimeUTC
	expired := false
	if w3c.Expiration != nil {
		if time.Now().UTC().After(w3c.Expiration.UTC()) {
			expired = true
		}
		expiresAt = common.ToPointer(TimeUTC(*w3c.Expiration))
	}

	proofs := getProofs(credential)

	return Credential{
		CredentialSubject:     w3c.CredentialSubject,
		CreatedAt:             TimeUTC(*w3c.IssuanceDate),
		Data:                  credential.Data.Bytes,
		Expired:               expired,
		ExpiresAt:             expiresAt,
		Id:                    credential.ID,
		ProofTypes:            proofs,
		RevNonce:              uint64(credential.RevNonce),
		Revoked:               credential.Revoked,
		SchemaHash:            credential.SchemaHash,
		SchemaType:            shortType(credential.SchemaType),
		SchemaUrl:             credential.SchemaURL,
		UserID:                credential.OtherIdentifier,
		SchemaTypeDescription: credential.SchemaTypeDescription,
		Version:               credential.Version,
		Updatable:             credential.Updatable,
	}
}

func shortType(id string) string {
	parts := strings.Split(id, "#")
	l := len(parts)
	if l == 0 {
		return ""
	}
	return parts[l-1]
}

func getProofs(credential *domain.Claim) []string {
	proofs := make([]string, 0)
	if credential.SignatureProof.Bytes != nil {
		proofs = append(proofs, string(verifiable.BJJSignatureProofType))
	}

	if credential.MtProof {
		proofs = append(proofs, string(verifiable.SparseMerkleTreeProof))
	}

	return proofs
}
