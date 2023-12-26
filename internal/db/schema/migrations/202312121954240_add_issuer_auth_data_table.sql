-- +goose Up
-- +goose StatementBegin
CREATE TABLE issuer_auth_data
(
    id         uuid NOT NULL,
    identifier text NOT NULL,
    "data"     jsonb NULL,
    CONSTRAINT fk_auth_claim_id FOREIGN KEY (id, identifier) REFERENCES public.claims (id, identifier),
    CONSTRAINT pk_auth_claim_id PRIMARY KEY (id, identifier)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS issuer_auth_data;
-- +goose StatementEnd
