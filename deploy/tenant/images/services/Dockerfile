FROM harbor.platform.rtx.local/proxy-dockerhub/library/python:3.12-slim
WORKDIR /opt
COPY poc/mlscan_poc.py /opt/mlscan/mlscan_poc.py
COPY deploy/stage2/service/mlscan_testing.py deploy/stage3/service/mlscan_analytics.py deploy/stage4/service/mlscan_integrations.py deploy/stage5/service/mlscan_ops.py /opt/svc/
COPY poc/formats.py /opt/formats/detector.py
COPY deploy/v2/auth/authz.py /opt/auth/
COPY deploy/i18n/i18n.py /opt/i18n/
COPY deploy/v2/db/pgclient.py /opt/pg/
COPY deploy/v2/data/s3/s3client.py /opt/s3/
COPY deploy/v3/ingest/quota.py deploy/v3/data/pool.py deploy/v3/data/objectrefs.py deploy/v3/ingest/hf.py /opt/v3ingest/
COPY deploy/v3/control/pq.py deploy/v3/control/tasks_sql.py deploy/v3/control/orchestrator.py deploy/v3/control/tenants.py deploy/v3/control/attest.py deploy/v3/control/leader.py /opt/v3control/
COPY deploy/v3/llm/classifier.py deploy/v3/llm/binding.py deploy/v3/llm/llm_env.py deploy/v3/llm/tetragon.py deploy/v3/llm/gguf.py deploy/v3/llm/xlsx.py deploy/v3/llm/promptset.py deploy/v3/llm/evaluators.py /opt/v3llm/
COPY deploy/v3/registry/images.py deploy/v3/registry/sbom.py /opt/v3registry/
COPY deploy/v3/analysis/static_stream.py deploy/v3/analysis/archive_walk.py deploy/v3/analysis/slice_selector.py deploy/v3/llm/gguf.py /opt/v3analysis/
COPY deploy/v3/security/evidence.py deploy/v3/security/kms.py /opt/v3security/
COPY deploy/v3/obs/metrics.py deploy/v3/obs/slo.py /opt/v3obs/
COPY deploy/v3/migration/migrate.py /opt/v3migration/
CMD ["python3"]
