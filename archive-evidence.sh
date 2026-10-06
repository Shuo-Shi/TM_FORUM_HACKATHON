#!/usr/bin/env bash
# Appends gateway lines to a durable file every 2 minutes, de-duplicated.
OUT=~/evidence/archive/gateway.log
touch "$OUT"
while true; do
  kubectl -n agentgateway-system logs deploy/modaas-agw --since=5m 2>/dev/null \
    | grep 'listener=llm' >> "$OUT"
  sort -u "$OUT" -o "$OUT"
  sleep 120
done
