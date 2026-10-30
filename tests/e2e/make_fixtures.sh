#!/usr/bin/env bash
# Подготовка реальных тестовых данных для операторского E2E (S1/S2/S3):
#   /tmp/real-model.safetensors   — настоящий safetensors (F32-тензоры)
#   /tmp/real-model-pack.zip      — настоящий архив (safetensors + config + pickle + вложенный zip)
#   /tmp/gemma-3-270m-it-Q8_0.gguf — реальный GGUF (копируется из PVC llama-models, если нет)
# Идемпотентно: существующие файлы не перезаписываются (кроме safetensors/zip — они детерминированы).
#   bash tests/e2e/make_fixtures.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-rtx}"

python3 - <<'PY'
import json, os, struct, zipfile, random
random.seed(7)

def safetensors(path, tensors):
    hdr, off, blobs = {}, 0, []
    for name, (shape, vals) in tensors.items():
        n = 1
        for d in shape:
            n *= d
        data = struct.pack("<%df" % n, *vals[:n])
        hdr[name] = {"dtype": "F32", "shape": list(shape), "data_offsets": [off, off + len(data)]}
        off += len(data); blobs.append(data)
    hj = json.dumps(hdr, separators=(",", ":")).encode()
    hj += b" " * (8 - (len(hj) % 8) if len(hj) % 8 else 0)
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hj))); f.write(hj)
        for b in blobs:
            f.write(b)
    return os.path.getsize(path)

vals = [random.uniform(-1, 1) for _ in range(256 * 64)]
print("safetensors:", safetensors("/tmp/real-model.safetensors",
                                  {"model.embed_tokens.weight": ((256, 64), vals)}), "байт")

class Evil:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))

import pickle
with open("/tmp/evil.pkl", "wb") as f:
    pickle.dump(Evil(), f)

with zipfile.ZipFile("/tmp/inner.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("nested/real.safetensors", open("/tmp/real-model.safetensors", "rb").read())
    z.writestr("nested/config.json", json.dumps({"model_type": "llama", "hidden_size": 256}))
with zipfile.ZipFile("/tmp/real-model-pack.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("weights/real-model.safetensors", open("/tmp/real-model.safetensors", "rb").read())
    z.writestr("config.json", json.dumps({"architectures": ["LlamaForCausalLM"], "model_type": "llama",
                                          "hidden_size": 256, "num_hidden_layers": 4}))
    z.writestr("tokenizer.json", json.dumps({"version": "1.0", "model": {"type": "BPE"}}))
    z.writestr("evil.pkl", open("/tmp/evil.pkl", "rb").read())
    z.writestr("nested/inner.zip", open("/tmp/inner.zip", "rb").read())
print("архив:", os.path.getsize("/tmp/real-model-pack.zip"), "байт")
PY

GGUF=/tmp/gemma-3-270m-it-Q8_0.gguf
if [ ! -f "$GGUF" ]; then
  echo "[fixtures] копирую реальный GGUF из PVC llama-models…"
  POD="fixtures-copy"
  cat <<Y | kubectl --context "$CTX" apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: $POD, namespace: mlscan-build}
spec:
  restartPolicy: Never
  containers:
  - name: c
    image: busybox:1.36
    command: ["sleep","1800"]
    volumeMounts: [{name: m, mountPath: /models, readOnly: true}]
  volumes:
  - name: m
    persistentVolumeClaim: {claimName: llama-models}
Y
  kubectl --context "$CTX" -n mlscan-build wait --for=condition=Ready "pod/$POD" --timeout=120s >/dev/null 2>&1
  kubectl --context "$CTX" -n mlscan-build cp "$POD:/models/gemma-3-270m-it-Q8_0.gguf" "$GGUF" >/dev/null 2>&1 \
    || echo "[fixtures] ВНИМАНИЕ: не удалось скопировать GGUF (S2-локально будет пропущен)"
  kubectl --context "$CTX" -n mlscan-build delete pod "$POD" --ignore-not-found >/dev/null 2>&1
fi
ls -la /tmp/real-model.safetensors /tmp/real-model-pack.zip "$GGUF" 2>/dev/null | awk '{print "  "$5" "$9}'
echo "[fixtures] готово"
