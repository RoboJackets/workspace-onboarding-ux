{{ range $key, $value := (key "workspace-onboarding-ux" | parseJSON) -}}
{{- $key | trimSpace -}}={{- $value | toJSON }}
{{ end -}}
SENTRY_ENVIRONMENT="production"
FLASK_CACHE_TYPE="RedisCache"
FLASK_CACHE_REDIS_URL="unix:///alloc/tmp/redis.sock?db=0&password={{ env "NOMAD_ALLOC_ID" }}"
FLASK_CELERY_BROKER_URL=redis+socket://:{{ env "NOMAD_ALLOC_ID" }}@/alloc/tmp/redis.sock?virtual_host=1
FLASK_CELERY_RESULT_BACKEND=redis+socket://:{{ env "NOMAD_ALLOC_ID" }}@/alloc/tmp/redis.sock?virtual_host=2
FLASK_ORG_CHART_NOTIFY_URL="https://org-chart.robojackets.org/api/import-google-workspace-user"
