FROM public.ecr.aws/docker/library/python:3.12-alpine
WORKDIR /operator
COPY requirements.txt .
# a design note Mechanism 2: the exact-pin constraints file requirements.txt references
# with `-c constraints/aws-sdk.txt`. pip resolves that path relative to the
# requirements file, so the copy must be in the image next to it. Refreshed from
# the canonical constraints/aws-sdk.txt by build-and-push.sh.
COPY constraints/aws-sdk.txt constraints/aws-sdk.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py /operator/
COPY shared_build/shared /operator/operators/shared/
COPY shared_build/shared /operator/shared/
RUN touch /operator/operators/__init__.py /operator/shared/__init__.py
# No --verbose: it puts botocore at DEBUG, which logs every signed request
# with the pod's session token (event 8acc8261, 2026-09-27).
CMD kopf run --namespace=$COMPONENT_NAMESPACE --namespace=${MODAAS_SYSTEM_NAMESPACE:-modaas-system} /operator/tool_operator.py
