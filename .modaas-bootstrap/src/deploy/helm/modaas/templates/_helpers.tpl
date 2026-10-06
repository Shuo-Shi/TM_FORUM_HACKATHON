{{/*
Expand the chart name.
*/}}
{{- define "modaas.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name (used by some sub-resources that need a unique
release-scoped name).
*/}}
{{- define "modaas.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label.
*/}}
{{- define "modaas.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels merged with .Values.commonLabels. Apply to every resource.
*/}}
{{- define "modaas.labels" -}}
helm.sh/chart: {{ include "modaas.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels — used in deployment.spec.selector and service.spec.selector.
Stable subset; never includes helm.sh/chart (which changes on upgrade).
*/}}
{{- define "modaas.selectorLabels" -}}
app.kubernetes.io/name: {{ .name }}
{{- end }}

{{/*
Compute the ServiceAccount name for a given component.
Usage: {{ include "modaas.serviceAccountName" (dict "Values" .Values "component" "model") }}
*/}}
{{- define "modaas.serviceAccountName" -}}
{{- $component := .component -}}
{{- $values := .Values -}}
{{- $cfg := index $values.operators $component | default dict -}}
{{- $cfg.name | default (printf "aws-%s-operator" $component) -}}
{{- end -}}

{{/*
Build a fully qualified image reference. Component-level overrides take
precedence over chart-wide defaults; falls back to chart appVersion when
tag is empty.
Usage: {{ include "modaas.image" (dict "Values" .Values "Chart" .Chart "component" "model") }}
*/}}
{{- define "modaas.image" -}}
{{- $values := .Values -}}
{{- $chart := .Chart -}}
{{- $component := .component -}}
{{- $cfg := index $values.operators $component | default dict -}}
{{- $img := $cfg.image | default dict -}}
{{- $registry := $img.registry | default "public.ecr.aws/modaas" -}}
{{- $repository := $img.repository | default "modaas" -}}
{{- $tag := $img.tag -}}
{{- if not $tag -}}
{{- $tag = $chart.AppVersion -}}
{{- end -}}
{{- /* Prefer an immutable digest when supplied. A mutable tag such as 'latest' combined with
       imagePullPolicy IfNotPresent means a freshly built image never actually lands: the kubelet
       reuses the cached layer and `rollout restart` still reports success. Pinning the digest here
       keeps helm the owner of .spec...image; pinning it with `kubectl set image` instead takes
       field ownership away from helm and makes every later `helm upgrade` fail with
       "conflict with kubectl-set". */ -}}
{{- if $img.digest -}}
{{- printf "%s/%s@%s" $registry $repository $img.digest -}}
{{- else -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- end -}}
{{- end -}}

{{/*
Image pull policy with the same fallback chain.
Usage: {{ include "modaas.imagePullPolicy" (dict "Values" .Values "component" "model") }}
*/}}
{{- define "modaas.imagePullPolicy" -}}
{{- $values := .Values -}}
{{- $component := .component -}}
{{- $cfg := index $values.operators $component | default dict -}}
{{- $img := $cfg.image | default dict -}}
{{- $img.pullPolicy | default "IfNotPresent" -}}
{{- end -}}

{{/*
Render IRSA annotation for a SA when an ARN is provided.
Usage:
  metadata:
    annotations:
      {{- include "modaas.irsaAnnotation" (dict "arn" .Values.operators.model.irsaRoleArn) | nindent 4 }}
*/}}
{{- define "modaas.irsaAnnotation" -}}
{{- with .arn -}}
eks.amazonaws.com/role-arn: {{ . | quote }}
{{- end -}}
{{- end -}}
