CREATE TABLE sagas (
    saga_id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    dag JSONB NOT NULL,
    state TEXT NOT NULL,
    current_node_id UUID,
    node_claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sagas_state ON sagas (state);
CREATE INDEX idx_sagas_name ON sagas (name);
CREATE INDEX idx_sagas_created_at ON sagas (created_at);
CREATE INDEX idx_sagas_current_node_id ON sagas (current_node_id);
CREATE INDEX idx_sagas_node_claimed_at ON sagas (node_claimed_at) WHERE current_node_id IS NOT NULL;

CREATE TABLE saga_events (
    id BIGSERIAL PRIMARY KEY,
    saga_id UUID NOT NULL REFERENCES sagas(saga_id) ON DELETE CASCADE,
    node_id BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    event_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_saga_events_saga_id ON saga_events (saga_id);
CREATE INDEX idx_saga_events_event_type ON saga_events (event_type);
CREATE INDEX idx_saga_events_saga_id_id ON saga_events (saga_id, id);
