DROP INDEX IF EXISTS idx_saga_events_saga_id_id;
DROP INDEX IF EXISTS idx_saga_events_event_type;
DROP INDEX IF EXISTS idx_saga_events_saga_id;

DROP INDEX IF EXISTS idx_sagas_node_claimed_at;
DROP INDEX IF EXISTS idx_sagas_current_node_id;
DROP INDEX IF EXISTS idx_sagas_created_at;
DROP INDEX IF EXISTS idx_sagas_name;
DROP INDEX IF EXISTS idx_sagas_state;

-- Drop tables (saga_events first due to foreign key constraint)
DROP TABLE IF EXISTS saga_events;
DROP TABLE IF EXISTS sagas;
