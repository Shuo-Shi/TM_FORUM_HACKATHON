# python:3.12-slim, matching pdp/Dockerfile rather than ai-gateway-pod's Alpine:
# boto3 on musl is avoidable friction and this service's one AWS dependency is boto3.
#
# Tag-pinned, not digest-pinned. That is inherited, not chosen: no MoDaaS image is
# digest-pinned and no image scanning exists anywhere in this repository. It means
# two builds a month apart can differ in their base layer with no diff here.
FROM public.ecr.aws/docker/library/python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Nothing from operators/shared/ -- but the evidence contract (a design note) IS a shared
# package, owned by core at <repo>/evidence/ and imported by this service and by
# evidence-service. `build-and-push.sh` refreshes evidence_build/evidence from the
# canonical copy as its FIRST step (the G00 drift class), and it lands at
# /app/evidence here so `import evidence.evidence_record` resolves the same way it
# does from the repo tree.
COPY *.py ./
COPY evidence_build/evidence ./evidence

EXPOSE 8080

# --limit-concurrency is LOAD-BEARING, not a far-outer net: uvicorn accumulates
# cycle.body in its protocol loop regardless of whether the ASGI app calls
# receive(), so this is the only bound on that buffer. It is sized from the same
# memory arithmetic as MAX_IN_FLIGHT (see config.py).
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port 8080 \
  --limit-concurrency ${LIMIT_CONCURRENCY:-128} --no-access-log"]
