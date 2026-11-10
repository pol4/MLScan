FROM harbor.platform.rtx.local/proxy-dockerhub/lmsysorg/sglang:v0.5.9
LABEL mlscan.engine.type="sglang"
LABEL mlscan.engine.arch="sm75"
COPY deploy/tenant/images/engine-sglang-sm75/sitecustomize.py /opt/sgl-sm75/sitecustomize.py
ENV PYTHONPATH=/opt/sgl-sm75
EXPOSE 8000
