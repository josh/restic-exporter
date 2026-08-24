{{- define "restic-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "restic-exporter.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "restic-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "restic-exporter.labels" -}}
helm.sh/chart: {{ include "restic-exporter.chart" . }}
{{ include "restic-exporter.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "restic-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "restic-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "restic-exporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "restic-exporter.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "restic-exporter.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{- define "restic-exporter.ageIdentitySecretName" -}}
{{- .Values.restic.ageIdentity.existingSecret | default .Values.restic.existingSecret -}}
{{- end -}}

{{- define "restic-exporter.validate" -}}
{{- if not (or .Values.restic.repository .Values.restic.existingSecret) -}}
{{- fail "set restic.repository, or restic.existingSecret holding RESTIC_REPOSITORY" -}}
{{- end -}}
{{- if and .Values.restic.ageIdentity.enabled (not (include "restic-exporter.ageIdentitySecretName" .)) -}}
{{- fail "restic.ageIdentity.enabled needs restic.ageIdentity.existingSecret or restic.existingSecret" -}}
{{- end -}}
{{- if and .Values.networkPolicy.ingress.enabled (not .Values.networkPolicy.ingress.from) -}}
{{- fail "networkPolicy.ingress.enabled needs the peers scraping metrics; set networkPolicy.ingress.from" -}}
{{- end -}}
{{- if and .Values.networkPolicy.egress.enabled (not (or .Values.networkPolicy.egress.repository.to .Values.networkPolicy.egress.extraRules)) -}}
{{- fail "networkPolicy.egress.enabled needs peers reaching restic.repository; set networkPolicy.egress.repository.to" -}}
{{- end -}}
{{- end -}}
