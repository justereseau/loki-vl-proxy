#!/bin/sh
# Pushes a mix of structured, JSON, logfmt and plain-text logs from a few
# services into VictoriaLogs (jsonline API) every second.
set -eu
trap 'exit 0' TERM INT
BASE="${VL_URL:-http://victorialogs:9428}"
URL="$BASE/insert/jsonline?_stream_fields=service.name,k8s.namespace.name,k8s.pod.name"

until curl -sf "$BASE/health" >/dev/null; do sleep 1; done
echo "pushing sample logs to $URL"

i=0
while true; do
  i=$((i + 1))
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  case $((i % 7)) in
    0) lvl=error; status=500 ;;
    1) lvl=warn; status=429 ;;
    2) lvl=debug; status=200 ;;
    *) lvl=info; status=200 ;;
  esac
  case $((i % 4)) in
    0) sev=ERROR ;;
    1) sev=WARNING ;;
    *) sev=INFO ;;
  esac
  dur=$(((i * 37) % 900))
  user=$((i % 13))
  pod=$((i % 3))
  amount=$(((i * 13) % 500))
  job=$((i % 4))
  took=$((dur / 3))
  items=$((i % 100))
  ipa=$((i % 4))
  ipb=$((i % 250))
  trace=$(printf '%032x' $((i * 7919)))

  {
    printf '{"_time":"%s","_msg":"GET /api/v1/users/%s %s %sms","service.name":"api","k8s.namespace.name":"shop","k8s.pod.name":"api-7f9c-%s","level":"%s","http.method":"GET","http.status_code":"%s","duration":"%sms","trace_id":"%s"}\n' \
      "$now" "$user" "$status" "$dur" "$pod" "$lvl" "$status" "$dur" "$trace"
    printf '{"_time":"%s","_msg":"{\\"level\\":\\"%s\\",\\"msg\\":\\"order processed\\",\\"order_id\\":%s,\\"amount\\":%s.99,\\"customer\\":\\"c%s\\"}","service.name":"checkout","k8s.namespace.name":"shop","k8s.pod.name":"checkout-5d8b-0"}\n' \
      "$now" "$lvl" "$i" "$amount" "$user"
    printf '{"_time":"%s","_msg":"level=%s msg=\\"job finished\\" job=sync-%s took=%sms items=%s","service.name":"worker","k8s.namespace.name":"batch","k8s.pod.name":"worker-0"}\n' \
      "$now" "$lvl" "$job" "$took" "$items"
    printf '{"_time":"%s","_msg":"connection from 10.0.%s.%s accepted","service.name":"gateway","k8s.namespace.name":"edge","k8s.pod.name":"gateway-1","severity_text":"%s"}\n' \
      "$now" "$ipa" "$ipb" "$sev"
  } | curl -s -o /dev/null -X POST -H 'Content-Type: application/stream+json' --data-binary @- "$URL" || echo "push failed"
  sleep 1
done
