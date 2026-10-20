import json
import os
import zipfile

OUT = os.path.join(os.path.dirname(__file__), "formats")
os.makedirs(OUT, exist_ok=True)


def w(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print("  ", name)


# 1) TorchServe .mar с handler-кодом (RCE при serve)
with zipfile.ZipFile(os.path.join(OUT, "evil_mar.mar"), "w") as z:
    z.writestr("MAR-INF/MANIFEST.json", json.dumps({"model": {"handler": "handler.py"}}))
    z.writestr("handler.py", "import os\nos.system('id')\n")
print("   evil_mar.mar")

# 2) config.json со ссылкой на удалённый код
w("evil_auto_map.json", json.dumps({"auto_map": {"AutoModel": "modeling_evil.Evil"}}).encode())

# 3) Keras .keras с Lambda
with zipfile.ZipFile(os.path.join(OUT, "evil.keras"), "w") as z:
    z.writestr("config.json", json.dumps({"class_name": "Lambda", "config": {"function": "eval"}}))
    z.writestr("metadata.json", "{}")
print("   evil.keras")

# 4) ONNX с external_data/custom ops
w("evil.onnx", b"\x08\x07" + b"external_data" + b"custom" + b"ai.onnx.contrib" + b"location")

# 5) HDF5 с признаками Lambda/__reduce__
w("evil.h5", b"\x89HDF\r\n\x1a\n" + b"Lambda" + b"__reduce__" + b"external link")

# 6) tokenizer_config с опасным Jinja chat_template (SSTI)
w("evil_tokenizer_config.json",
  json.dumps({"chat_template": "{{ cycler.__init__.__globals__.os.popen('id').read() }}"}).encode())

# 7) GGUF с chat_template и опасными конструкциями
w("evil.gguf", b"GGUF" + b"chat_template" + b"__class__" + b"__globals__")

# 8) безобидный конфиг
w("benign.json", json.dumps({"hidden_size": 8, "num_layers": 2}).encode())
