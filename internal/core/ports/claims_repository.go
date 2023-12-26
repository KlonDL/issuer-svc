package ports

import (
	"context"

	"github.com/google/uuid"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/polygonid/sh-id-platform/internal/core/domain"
	"github.com/polygonid/sh-id-platform/internal/db"
)

// ClaimsRepository is the interface that defines the available methods
type ClaimsRepository interface {
	Save(ctx context.Context, conn db.Querier, claimI domain.ClaimPublicInfoI) (uuid.UUID, error)
	SaveAuthClaim(ctx context.Context, conn db.Querier, claim *domain.Claim) (uuid.UUID, error)
	Revoke(ctx context.Context, conn db.Querier, revocation *domain.Revocation) error
	RevokeNonce(ctx context.Context, conn db.Querier, revocation *domain.Revocation) error
	GetByRevocationNonce(ctx context.Context, conn db.Querier, identifier *w3c.DID, revocationNonce domain.RevNonceUint64) (*domain.ClaimPublicInfo, error)
	GetByIdAndIssuer(ctx context.Context, conn db.Querier, identifier *w3c.DID, claimID uuid.UUID) (*domain.ClaimPublicInfo, error)
	GetByIdAndIssuerAuth(ctx context.Context, conn db.Querier, identifier *w3c.DID, claimID uuid.UUID) (*domain.Claim, error)
	FindOneClaimBySchemaHash(ctx context.Context, conn db.Querier, subject *w3c.DID, schemaHash string) (*domain.ClaimPublicInfo, error)
	GetAllByIssuerID(ctx context.Context, conn db.Querier, identifier w3c.DID, filter *ClaimsFilter) ([]*domain.ClaimPublicInfo, error)
	GetAllByIssuerIDAuth(ctx context.Context, conn db.Querier, issuerID w3c.DID, filter *ClaimsFilter) ([]*domain.Claim, error)
	GetNonRevokedByConnectionAndIssuerID(ctx context.Context, conn db.Querier, connID uuid.UUID, issuerID w3c.DID) ([]*domain.ClaimPublicInfo, error)
	GetAllByState(ctx context.Context, conn db.Querier, did *w3c.DID, state *merkletree.Hash) (claims []domain.ClaimPublicInfo, err error)
	GetAllByStateWithMTProof(ctx context.Context, conn db.Querier, did *w3c.DID, state *merkletree.Hash) (claims []domain.ClaimPublicInfo, err error)
	UpdateState(ctx context.Context, conn db.Querier, claim *domain.ClaimPublicInfo) (int64, error)
	GetAuthClaimsForPublishing(ctx context.Context, conn db.Querier, identifier *w3c.DID, publishingState string, schemaHash string) ([]*domain.ClaimPublicInfo, error)
	UpdateClaimMTP(ctx context.Context, conn db.Querier, claim *domain.ClaimPublicInfo) (int64, error)
	Delete(ctx context.Context, conn db.Querier, id uuid.UUID) error
	GetClaimsIssuedForUser(ctx context.Context, conn db.Querier, identifier w3c.DID, userDID w3c.DID, linkID uuid.UUID) ([]*domain.Claim, error)
	GetByStateIDWithMTPProof(ctx context.Context, conn db.Querier, did *w3c.DID, state string) (claims []*domain.ClaimPublicInfo, err error)
}
