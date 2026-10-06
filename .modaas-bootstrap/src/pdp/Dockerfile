FROM public.ecr.aws/docker/library/python:3.12-slim

# Cedar (cedarpy) ships pre-built manylinux wheels on PyPI for x86_64 +
# aarch64, so we can use slim instead of alpine and skip the rust toolchain.
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir "setuptools<80" wheel && \
    pip install --no-cache-dir -r requirements.txt

COPY *.py .

USER nobody
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; \
    sys.exit(0 if urllib.request.urlopen('http://localhost:8080/healthz', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
