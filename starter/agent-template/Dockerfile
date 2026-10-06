# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Reference only — new-agent.sh does not build from this file directly. It
# builds through static/reference-impl/build-agent-image.sh TARGET=agentcore,
# which generates an equivalent Dockerfile on the fly (same base image, same
# ENTRYPOINT shape, plus the ADOT observability layer AgentCore needs) and
# runs the build in CodeBuild on an arm64 host, because AgentCore Runtime
# accepts linux/arm64 images only and the IDE's own Docker daemon has no
# push permission (see Module 9, "Build the image"). This file exists so you
# can read exactly what gets built, and so you can build+push it yourself
# through your own arm64 CI if you ever move off this workshop's CodeBuild
# path.
FROM public.ecr.aws/docker/library/python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir strands-agents[openai]==1.57.2 bedrock-agentcore==1.24.0 \
    mcp==1.30.0 aws-opentelemetry-distro==0.21.0
ENV OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=urllib,urllib3,botocore,boto3
COPY agent.py /app/agent.py
EXPOSE 8080
ENTRYPOINT ["opentelemetry-instrument", "python3", "/app/agent.py"]
