-- Схема v3 (P0+). Дополняет v2-схему; применяется поверх БД mlscan.
-- object_refs: ссылки тенантов на объекты общего пула (дедуп между тенантами, refcount для GC).
CREATE TABLE IF NOT EXISTS object_refs (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  name TEXT,
  size BIGINT,
  refcount INT NOT NULL DEFAULT 1,
  first_seen TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now(),
  UNIQUE (tenant_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_object_refs_sha ON object_refs(sha256);
CREATE INDEX IF NOT EXISTS idx_object_refs_tenant ON object_refs(tenant_id);

-- tasks: персистентная очередь сканов с приоритетами (P2)
CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  priority TEXT NOT NULL,
  rank INT NOT NULL,
  seq BIGSERIAL,
  payload TEXT,
  status TEXT NOT NULL DEFAULT 'queued',
  created TIMESTAMPTZ DEFAULT now(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_dequeue ON tasks(status, rank, seq);
