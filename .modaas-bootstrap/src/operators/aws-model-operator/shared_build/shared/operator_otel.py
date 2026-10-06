"""W4.B: Operator-side OTel decorator. Fail-soft when tracing not initialized."""
import functools
import inspect
from typing import Optional

try:
    from opentelemetry import trace
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


def traced(span_name: str, attrs: Optional[dict] = None):
    """Decorator: wrap function in OTel span. Records exceptions; re-raises.

    Works with both sync and async functions. Fail-soft: if OTel is not
    installed, the decorated function runs unchanged.
    """
    def deco(fn):
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapped(*args, **kwargs):
                if not _OTEL_AVAILABLE:
                    return await fn(*args, **kwargs)
                tracer = trace.get_tracer("modaas.operator")
                with tracer.start_as_current_span(span_name) as span:
                    if attrs:
                        for k, v in attrs.items():
                            span.set_attribute(k, v)
                    try:
                        return await fn(*args, **kwargs)
                    except Exception as e:
                        span.record_exception(e)
                        raise
            return async_wrapped
        else:
            @functools.wraps(fn)
            def wrapped(*args, **kwargs):
                if not _OTEL_AVAILABLE:
                    return fn(*args, **kwargs)
                tracer = trace.get_tracer("modaas.operator")
                with tracer.start_as_current_span(span_name) as span:
                    if attrs:
                        for k, v in attrs.items():
                            span.set_attribute(k, v)
                    try:
                        return fn(*args, **kwargs)
                    except Exception as e:
                        span.record_exception(e)
                        raise
            return wrapped
    return deco
