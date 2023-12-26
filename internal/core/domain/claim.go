package domain

import (
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/jackc/pgtype"

	"github.com/polygonid/sh-id-platform/internal/common"
)

// CoreClaim is an alias for the core.Claim struct
type CoreClaim core.Claim

// Claim struct
type Claim struct {
	SchemaURL             string       `json:"schema_url"`
	SchemaType            string       `json:"schema_type"`
	OtherIdentifier       string       `json:"other_identifier"`
	Updatable             bool         `json:"updatable"`
	Version               uint32       `json:"version"`
	Data                  pgtype.JSONB `json:"data"`
	LinkID                *uuid.UUID   `json:"-"`
	CreatedAt             time.Time    `json:"-"`
	SchemaTypeDescription *string      `json:"schema_type_description"`
	ClaimPublicInfo
}

// Credentials is the type of array of credential
type Credentials []*Claim

// FromClaimer TODO add description
func FromClaimer(claim *core.Claim, schemaURL, schemaType string) (*Claim, error) {
	otherIdentifier := ""
	id, err := claim.GetID()
	switch err {
	case core.ErrNoID:
	case nil:
		otherDID, errIn := core.ParseDIDFromID(id)
		if errIn != nil {
			return nil, fmt.Errorf("ID is not DID: %w", err)
		}
		otherIdentifier = otherDID.String()

	default:
		return nil, fmt.Errorf("can't get ID: %w", err)
	}

	var expiration int64
	if expirationDate, ok := claim.GetExpirationDate(); ok {
		expiration = expirationDate.Unix()
	}

	hindex, err := claim.HIndex()
	if err != nil {
		return nil, err
	}

	sb := claim.GetSchemaHash()
	schemaHash := hex.EncodeToString(sb[:])
	res := Claim{
		ClaimPublicInfo: ClaimPublicInfo{
			SchemaHash: schemaHash,
			Expiration: expiration,
			RevNonce:   RevNonceUint64(claim.GetRevocationNonce()),
			CoreClaim:  CoreClaim(*claim),
			HIndex:     hindex.String(),
		},
		SchemaURL:       schemaURL,
		SchemaType:      schemaType,
		OtherIdentifier: otherIdentifier,
		Updatable:       claim.GetFlagUpdatable(),
		Version:         claim.GetVersion(),
	}

	return &res, nil
}

// Value implementation of valuer interface to convert CoreClaim value for storing in Postgres
func (c CoreClaim) Value() (driver.Value, error) {
	cc := core.Claim(c)
	jsonStr, err := json.Marshal(cc)
	return string(jsonStr), err
}

// Scan TODO
func (c *CoreClaim) Scan(value interface{}) error {
	valueStr, ok := value.(string)
	if !ok {
		return fmt.Errorf("invalid value type, expected string")
	}
	var claim core.Claim
	err := json.Unmarshal([]byte(valueStr), &claim)
	if err != nil {
		return err
	}
	*c = CoreClaim(claim)
	return nil
}

// Get returns the value of the core claim
func (c *CoreClaim) Get() *core.Claim {
	return (*core.Claim)(c)
}

// BuildTreeState returns circuits.TreeState structure
func BuildTreeState(state, claimsTreeRoot, revocationTreeRoot, rootOfRoots *string) (circuits.TreeState, error) {
	return circuits.TreeState{
		State:          common.StrMTHex(state),
		ClaimsRoot:     common.StrMTHex(claimsTreeRoot),
		RevocationRoot: common.StrMTHex(revocationTreeRoot),
		RootOfRoots:    common.StrMTHex(rootOfRoots),
	}, nil
}

//func (c *Claim) GetID() uuid.UUID {
//	return c.ID
//}
//
//func (c *Claim) GetIdentifier() *string {
//	return c.Identifier
//}
//
//func (c *Claim) GetIssuer() string {
//	return c.Issuer
//}
//
//func (c *Claim) GetRevNonce() RevNonceUint64 {
//	return c.RevNonce
//}
//
//func (c *Claim) GetRevoked() bool {
//	return c.Revoked
//}
//
//func (c *Claim) SetRevoked(revoked bool) {
//	c.Revoked = revoked
//}
//
//func (c *Claim) GetCoreClaim() CoreClaim {
//	return c.CoreClaim
//}
//
//func (c *Claim) GetSignatureProof() pgtype.JSONB {
//	return c.SignatureProof
//}
//
//func (c *Claim) GetCredentialStatusRaw() pgtype.JSONB {
//	return c.CredentialStatus
//}

func (c *Claim) ConvertToClaimPublicInfo() *ClaimPublicInfo {
	return &c.ClaimPublicInfo
}

// GetBJJSignatureProof2021 TBD
func (c *Claim) GetBJJSignatureProof2021() (*verifiable.BJJSignatureProof2021, error) {
	var sigProof verifiable.BJJSignatureProof2021
	err := c.SignatureProof.AssignTo(&sigProof)
	if err != nil {
		return &sigProof, err
	}
	return &sigProof, nil
}

// GetVerifiableCredential TBD
func (c *Claim) GetVerifiableCredential() (verifiable.W3CCredential, error) {
	var vc verifiable.W3CCredential
	err := c.Data.AssignTo(&vc)
	if err != nil {
		return vc, err
	}
	return vc, nil
}

// GetCircuitIncProof TBD
func (c *Claim) GetCircuitIncProof() (circuits.MTProof, error) {
	var proof verifiable.Iden3SparseMerkleTreeProof
	err := c.MTPProof.AssignTo(&proof)
	if err != nil {
		return circuits.MTProof{}, err
	}

	return circuits.MTProof{
		Proof: proof.MTP,
		TreeState: circuits.TreeState{
			State:          common.StrMTHex(proof.IssuerData.State.Value),
			ClaimsRoot:     common.StrMTHex(proof.IssuerData.State.ClaimsTreeRoot),
			RevocationRoot: common.StrMTHex(proof.IssuerData.State.RevocationTreeRoot),
			RootOfRoots:    common.StrMTHex(proof.IssuerData.State.RootOfRoots),
		},
	}, nil
}

// NewClaimModel creates domain.Claim with common fields filled from core.Claim
func NewClaimModel(jsonSchemaURL string, credentialType string, coreClaim core.Claim, did *w3c.DID) (*Claim, error) {
	hindex, err := coreClaim.HIndex()
	if err != nil {
		return nil, errors.Join(err)
	}

	schemaHash := coreClaim.GetSchemaHash()

	claimModel := Claim{
		ClaimPublicInfo: ClaimPublicInfo{
			SchemaHash: hex.EncodeToString(schemaHash[:]),
			RevNonce:   RevNonceUint64(coreClaim.GetRevocationNonce()),
			CoreClaim:  CoreClaim(coreClaim),
			HIndex:     hindex.String(),
		},
		SchemaURL:  jsonSchemaURL,
		SchemaType: credentialType,
		Updatable:  coreClaim.GetFlagUpdatable(),
		Version:    coreClaim.GetVersion(),
	}

	if did != nil {
		var claimID, id core.ID
		id, err = core.IDFromDID(*did)
		if err != nil {
			return nil, err
		}

		claimID, err = coreClaim.GetID()
		if err != nil {
			return nil, nil
		}

		if claimID != id {
			return nil, errors.New("claim has ID, but it's not match with DID")
		}
		claimModel.OtherIdentifier = did.String()
	} else {
		_, err = coreClaim.GetID()
		if !errors.Is(err, core.ErrNoID) {
			return nil, errors.New("claim has ID, but no DID")
		}
	}

	if expDate, ok := coreClaim.GetExpirationDate(); ok {
		claimModel.Expiration = expDate.Unix()
	}

	return &claimModel, nil
}

// GetCredentialStatus returns CredentialStatus deserialized object
func (c *Claim) GetCredentialStatus() (*verifiable.CredentialStatus, error) {
	cStatus := new(verifiable.CredentialStatus)
	err := c.CredentialStatus.AssignTo(cStatus)
	if err != nil {
		return nil, err
	}
	return cStatus, nil
}

type ClaimPublicInfoI interface {
	GetID() uuid.UUID
	GetIdentifier() *string
	GetIssuer() string
	GetRevNonce() RevNonceUint64
	GetRevoked() bool
	SetRevoked(revoked bool)
	GetCoreClaim() CoreClaim
	GetSignatureProof() pgtype.JSONB
	GetCredentialStatusRaw() pgtype.JSONB
	GetBJJSignatureProof2021() (*verifiable.BJJSignatureProof2021, error)
	GetCircuitIncProof() (circuits.MTProof, error)
	ConvertToClaimPublicInfo() *ClaimPublicInfo
}

type ClaimPublicInfo struct {
	ID               uuid.UUID       `json:"-"`
	Identifier       *string         `json:"identifier"`
	Issuer           string          `json:"issuer"`
	SchemaHash       string          `json:"schema_hash"`
	Expiration       int64           `json:"expiration"`
	RevNonce         RevNonceUint64  `json:"rev_nonce"`
	Revoked          bool            `json:"revoked"`
	CoreClaim        CoreClaim       `json:"core_claim"`
	MTPProof         pgtype.JSONB    `json:"mtp_proof"`
	SignatureProof   pgtype.JSONB    `json:"signature_proof"`
	IdentityState    *string         `json:"-"`
	CredentialStatus pgtype.JSONB    `json:"credential_status"`
	HIndex           string          `json:"-"`
	MtProof          bool            `json:"mt_poof"`
	Status           *IdentityStatus `json:"status"`
}

func (c *ClaimPublicInfo) GetID() uuid.UUID {
	return c.ID
}

func (c *ClaimPublicInfo) GetIdentifier() *string {
	return c.Identifier
}

func (c *ClaimPublicInfo) GetIssuer() string {
	return c.Issuer
}

func (c *ClaimPublicInfo) GetRevNonce() RevNonceUint64 {
	return c.RevNonce
}

func (c *ClaimPublicInfo) GetRevoked() bool {
	return c.Revoked
}

func (c *ClaimPublicInfo) SetRevoked(revoked bool) {
	c.Revoked = revoked
}

func (c *ClaimPublicInfo) GetCoreClaim() CoreClaim {
	return c.CoreClaim
}

func (c *ClaimPublicInfo) GetSignatureProof() pgtype.JSONB {
	return c.SignatureProof
}

func (c *ClaimPublicInfo) GetCredentialStatusRaw() pgtype.JSONB {
	return c.CredentialStatus
}

func (c *ClaimPublicInfo) ConvertToClaimPublicInfo() *ClaimPublicInfo {
	return c
}

// GetBJJSignatureProof2021 TBD
func (c *ClaimPublicInfo) GetBJJSignatureProof2021() (*verifiable.BJJSignatureProof2021, error) {
	var sigProof verifiable.BJJSignatureProof2021
	err := c.SignatureProof.AssignTo(&sigProof)
	if err != nil {
		return &sigProof, err
	}
	return &sigProof, nil
}

func (c *ClaimPublicInfo) GetCircuitIncProof() (circuits.MTProof, error) {
	var proof verifiable.Iden3SparseMerkleTreeProof
	err := c.MTPProof.AssignTo(&proof)
	if err != nil {
		return circuits.MTProof{}, err
	}

	return circuits.MTProof{
		Proof: proof.MTP,
		TreeState: circuits.TreeState{
			State:          common.StrMTHex(proof.IssuerData.State.Value),
			ClaimsRoot:     common.StrMTHex(proof.IssuerData.State.ClaimsTreeRoot),
			RevocationRoot: common.StrMTHex(proof.IssuerData.State.RevocationTreeRoot),
			RootOfRoots:    common.StrMTHex(proof.IssuerData.State.RootOfRoots),
		},
	}, nil
}
