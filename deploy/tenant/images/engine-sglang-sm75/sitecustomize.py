"""SGLang v0.5.9 compatibility shim for Turing (sm_75) GPUs.

Upstream `sgl_kernel` in v0.5.9 is built for sm_80+ only, so RMSNorm/SiLU fail with
"no kernel image is available". Replace those ops with pure-torch implementations.
Attention/sampling use torch_native/pytorch backends (set by the job command).
"""
import torch

try:
    import sgl_kernel as _sk
except Exception:  # pragma: no cover - no GPU / import failure
    _sk = None

if _sk is not None:
    def _rmsnorm(x, w, eps, out=None):
        orig = x.dtype
        xf = x.float()
        v = xf.pow(2).mean(dim=-1, keepdim=True)
        y = (xf * torch.rsqrt(v + eps) * w.float()).to(orig)
        if out is not None:
            out.copy_(y)
            return out
        return y

    def _fused_add_rmsnorm(x, residual, w, eps):
        residual.add_(x)
        x.copy_(_rmsnorm(residual, w, eps))

    def _silu_and_mul(x, out):
        d = x.shape[-1] // 2
        out.copy_(torch.nn.functional.silu(x[..., :d]) * x[..., d:])

    _sk.rmsnorm = _rmsnorm
    _sk.fused_add_rmsnorm = _fused_add_rmsnorm
    _sk.silu_and_mul = _silu_and_mul
