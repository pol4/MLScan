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

-- L0: профили моделей (классификация LLM) и bundle (образ движка + модель + версии)
CREATE TABLE IF NOT EXISTS model_profiles (
  sha256 TEXT PRIMARY KEY,
  is_llm BOOLEAN NOT NULL DEFAULT false,
  family TEXT DEFAULT '',
  confidence REAL DEFAULT 0,
  evidence TEXT DEFAULT '[]',
  suggested_engines TEXT DEFAULT '[]',
  source TEXT DEFAULT 'auto',
  updated TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bundles (
  bundle_id TEXT PRIMARY KEY,
  engine_image TEXT NOT NULL,
  model_sha256 TEXT NOT NULL,
  engine_manifest TEXT DEFAULT '{}',
  prompt_set TEXT DEFAULT '',
  detectors TEXT DEFAULT '',
  policy TEXT DEFAULT '',
  tenant TEXT DEFAULT '',
  created TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bundles_model ON bundles(model_sha256);

-- L1a: реестр образов движков (digest, источник, подпись/SBOM, ключ OCI-архива в S3)
CREATE TABLE IF NOT EXISTS registry_images (
  digest TEXT PRIMARY KEY,
  ref TEXT,
  source TEXT,
  size BIGINT DEFAULT 0,
  signature TEXT DEFAULT '',
  sbom TEXT DEFAULT '',
  stored_key TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'registered',
  created TIMESTAMPTZ DEFAULT now()
);

-- L2: события eBPF/Tetragon (наблюдение за LLM-инференсом) и смапленные находки
CREATE TABLE IF NOT EXISTS llm_events (
  id BIGSERIAL PRIMARY KEY,
  scan_id TEXT,
  check_id TEXT,
  severity TEXT,
  phase TEXT,
  probe_id TEXT,
  evidence TEXT,
  nonce TEXT,
  created TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_llm_events_scan ON llm_events(scan_id);

-- L3: наборы тестов (XLSX→БД) и оценка ответов
CREATE TABLE IF NOT EXISTS prompt_sets (
  version TEXT PRIMARY KEY,
  name TEXT,
  cases TEXT,
  warnings TEXT,
  errors TEXT,
  active BOOLEAN NOT NULL DEFAULT false,
  created TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS llm_prompts (
  prompt_set TEXT NOT NULL,
  id TEXT,
  domain TEXT,
  prompt TEXT,
  reference TEXT,
  criticality INT,
  severity TEXT,
  weight INT,
  tolerance REAL,
  policy_class TEXT,
  class_reviewed BOOLEAN,
  PRIMARY KEY (prompt_set, id)
);
CREATE TABLE IF NOT EXISTS llm_scores (
  scan_id TEXT,
  prompt_set TEXT,
  passed INT,
  total INT,
  safety_fail INT,
  pass_rate REAL,
  details TEXT,
  created TIMESTAMPTZ DEFAULT now()
);

-- L4: вердикты на уровне bundle + подписанные аттестации
CREATE TABLE IF NOT EXISTS bundle_verdicts (
  bundle_id TEXT PRIMARY KEY,
  verdict TEXT,
  action TEXT,
  coverage TEXT,
  metrics TEXT,
  statement TEXT,
  attestation_digest TEXT,
  signature TEXT,
  created TIMESTAMPTZ DEFAULT now()
);

-- L0/U1: тип артефакта в скане (badge «Engine image» и т.п.)
ALTER TABLE scans ADD COLUMN IF NOT EXISTS kind TEXT;

-- P2/U3: регистр версий детекторов
CREATE TABLE IF NOT EXISTS detector_versions (
  name TEXT PRIMARY KEY, version TEXT, digest TEXT, updated TIMESTAMPTZ DEFAULT now()
);

-- L3/U9: ручное переопределение «домен → класс policy»
CREATE TABLE IF NOT EXISTS domain_class_map (
  domain TEXT PRIMARY KEY, policy_class TEXT, reviewed BOOLEAN DEFAULT true,
  updated TIMESTAMPTZ DEFAULT now()
);

-- H1/U11: фоновые загрузки с HF (не зависят от браузера, с докачкой)
CREATE TABLE IF NOT EXISTS hf_downloads (
  id TEXT PRIMARY KEY, tenant TEXT, repo_id TEXT, revision TEXT, quantization TEXT,
  files TEXT, bytes_total BIGINT DEFAULT 0, bytes_done BIGINT DEFAULT 0,
  status TEXT DEFAULT 'queued', error TEXT, created TIMESTAMPTZ DEFAULT now(),
  updated TIMESTAMPTZ DEFAULT now()
);

-- §10: HF-токены (per-tenant, хранятся зашифрованно/маскированно)
CREATE TABLE IF NOT EXISTS hf_tokens (tenant TEXT PRIMARY KEY, token_enc TEXT, updated TIMESTAMPTZ DEFAULT now());

-- §10: привязка движка и bundle к HF-загрузке
ALTER TABLE hf_downloads ADD COLUMN IF NOT EXISTS engine_image TEXT;
ALTER TABLE hf_downloads ADD COLUMN IF NOT EXISTS bundle_id TEXT;
ALTER TABLE hf_downloads ADD COLUMN IF NOT EXISTS model_sha256 TEXT;

-- N2: запуски теста bundle (оркестрация инференса: job -> набор вопросов -> /llm/score -> вердикт)
CREATE TABLE IF NOT EXISTS bundle_tests (
  bundle_id TEXT PRIMARY KEY,
  scan_id TEXT DEFAULT '',
  job TEXT DEFAULT '',
  namespace TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'created',
  run_token TEXT DEFAULT '',
  gpu BOOLEAN DEFAULT true,
  error TEXT DEFAULT '',
  created TIMESTAMPTZ DEFAULT now(),
  updated TIMESTAMPTZ DEFAULT now()
);

-- N3: append-only журнал решений gate (аудит: что решили, по какой модели/образу, с какой аттестацией)
CREATE TABLE IF NOT EXISTS gate_decisions (
  id BIGSERIAL PRIMARY KEY,
  source TEXT NOT NULL,
  image TEXT DEFAULT '',
  model_sha256 TEXT DEFAULT '',
  verdict TEXT DEFAULT '',
  decision TEXT NOT NULL,
  attestation_digest TEXT DEFAULT '',
  signature TEXT DEFAULT '',
  payload TEXT DEFAULT '',
  created TIMESTAMPTZ DEFAULT now()
);
