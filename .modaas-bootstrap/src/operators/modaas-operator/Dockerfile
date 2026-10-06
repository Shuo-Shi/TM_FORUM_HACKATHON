# MoDaaS v2 operator — single binary, plugin-driven.
FROM public.ecr.aws/docker/library/python:3.12-slim

WORKDIR /operator

# Create non-root user with a proper passwd entry (kopf reads getpwuid)
RUN groupadd -g 1000 modaas && \
    useradd -u 1000 -g 1000 -m -s /bin/false modaas

COPY requirements.txt ./
# a design note Mechanism 2: the exact-pin constraints file requirements.txt references
# with `-c constraints/aws-sdk.txt`. pip resolves that path relative to the
# requirements file, so the copy must sit next to it in the build context.
COPY constraints/aws-sdk.txt constraints/aws-sdk.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source — preserve package structure
COPY main.py ./
COPY base/ ./base/
COPY providers/ ./providers/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/operator \
    LOG_LEVEL=INFO \
    HOME=/tmp

USER 1000:1000

CMD ["kopf", "run", "--standalone", "--all-namespaces", "/operator/main.py"]
