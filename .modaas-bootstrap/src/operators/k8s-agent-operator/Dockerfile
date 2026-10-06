# k8s-agent-operator — AgentConfig, provider=kubernetesPod (a design note).
#
# Shared code is copied to BOTH import roots because operators/shared modules
# carry `try: from shared.X ... except ImportError: from operators.shared.X ...`
# fallbacks. A module reachable by only one of the two paths breaks only inside
# the deployed image, never in the test run -- the a design note silent class.
FROM public.ecr.aws/docker/library/python:3.12-alpine
WORKDIR /operator
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py /operator/
COPY shared_build/shared /operator/operators/shared/
COPY shared_build/shared /operator/shared/
RUN touch /operator/operators/__init__.py /operator/shared/__init__.py
# No --verbose: it puts botocore at DEBUG, which logs every signed request
# with the pod's session token (event 8acc8261, 2026-09-27).
CMD kopf run --namespace=$COMPONENT_NAMESPACE --namespace=${MODAAS_SYSTEM_NAMESPACE:-modaas-system} /operator/k8s_agent_operator.py
