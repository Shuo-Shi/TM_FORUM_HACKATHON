#!/usr/bin/env bash
SCEN="${1:-S1-fronthaul-degradation}"
START=$(date -u +%FT%TZ)
source <(bash $HOME/starter/run-team.sh "$SCEN" | tee /dev/stderr | grep '^export CID=')
END=$(date -u +%FT%TZ)
kubectl get --raw "/api/v1/namespaces/components/services/audit-store:8080/proxy/timeline?cid=$CID" \
  > ~/evidence/ledger-$CID.txt
python3 /tmp/score-run.py "$CID" "$SCEN" ~/evidence/ledger-$CID.txt; RC=$?
echo "$CID,$SCEN,$START,$END,score_exit=$RC" >> ~/evidence/run-ids.txt
echo "logged $CID"
