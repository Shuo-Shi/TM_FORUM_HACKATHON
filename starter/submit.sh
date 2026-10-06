#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# submit.sh <team-name> — package your judgement-day artefacts and hand them
# in, per the challenge brief's "How you hand in" step.
#
# Packages ~/evidence/, register.yaml, gap-list.md, run-ids.txt and (if
# present) sketch.png/sketch.jpg into submission-<team>-<UTC>.zip, uploads it
# to your team's evidence bucket, and prints a short-lived presigned URL (tied to this IDE session). The zip
# is always kept locally too — the account is torn down at the end of the
# event, so the upload is not optional, but neither is having your own copy
# before you trust the network.
#
# Reads the bucket name from the environment (TEAM_EVIDENCE_BUCKET) or
# discovers it from the cluster's own CloudFormation stack outputs — never
# hardcoded, never an account id typed by hand.
#
# Usage:
#   bash submit.sh my-team
#   TEAM_EVIDENCE_BUCKET=team-evidence-abc123 bash submit.sh my-team
#
# Before running this: write run-ids.txt (one run id per line: the two named
# runs the brief asks for, one passing and one breaching) and gap-list.md
# (copy and fill in the template next to this script) in your working
# directory, or pass --dir to point at where they live.
set -euo pipefail

TEAM="${1:-}"
[ -n "$TEAM" ] || { echo "usage: $0 <team-name> [--dir WORKDIR] [--evidence-dir DIR]" >&2; exit 2; }
shift || true

WORKDIR="."
EVIDENCE_DIR="$HOME/evidence"
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) WORKDIR="${2:-.}"; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR="${2:-$HOME/evidence}"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

if ! printf '%s' "$TEAM" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'; then
  echo "team name '$TEAM' should be short, plain letters/digits/-/_ (it becomes part of a filename and an S3 key)" >&2
  exit 2
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
ZIP_NAME="submission-${TEAM}-${STAMP}.zip"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "staging artefacts for team '$TEAM'..."

if [ -d "$EVIDENCE_DIR" ]; then
  cp -R "$EVIDENCE_DIR" "$STAGE/evidence"
  echo "  evidence/     from $EVIDENCE_DIR ($(find "$STAGE/evidence" -type f | wc -l | tr -d ' ') file(s))"
else
  echo "  evidence/     MISSING — no directory at $EVIDENCE_DIR (run pull-evidence.sh first)" >&2
fi

for f in register.yaml gap-list.md run-ids.txt; do
  if [ -f "$WORKDIR/$f" ]; then
    cp "$WORKDIR/$f" "$STAGE/$f"
    echo "  $f  from $WORKDIR/$f"
  else
    echo "  $f  MISSING at $WORKDIR/$f" >&2
  fi
done

SKETCH=""
for candidate in "$WORKDIR"/sketch.png "$WORKDIR"/sketch.jpg "$WORKDIR"/sketch.jpeg; do
  [ -f "$candidate" ] && { cp "$candidate" "$STAGE/"; SKETCH="$candidate"; break; }
done
if [ -n "$SKETCH" ]; then
  echo "  sketch        from $SKETCH"
else
  echo "  sketch        MISSING — the brief asks for a one-page architecture sketch (a whiteboard photo is fine); drop sketch.png or sketch.jpg in $WORKDIR" >&2
fi

MANIFEST="$STAGE/MANIFEST.txt"
{
  echo "team: $TEAM"
  echo "packaged (UTC): $STAMP"
  echo "contents:"
  (cd "$STAGE" && find . -type f | sed 's#^\./##' | sort)
} > "$MANIFEST"

LOCAL_ZIP="./${ZIP_NAME}"
(cd "$STAGE" && zip -qr "$(cd - >/dev/null && pwd)/${ZIP_NAME}" .)
echo "wrote $(du -h "$LOCAL_ZIP" 2>/dev/null | cut -f1) -> $LOCAL_ZIP (kept locally regardless of upload result)"

# ── discover the bucket, upload, presign ──────────────────────────────────
BUCKET="${TEAM_EVIDENCE_BUCKET:-}"
if [ -z "$BUCKET" ]; then
  REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
  BUCKET=$(aws cloudformation describe-stacks --region "$REGION" \
    --query "Stacks[].Outputs[?OutputKey=='TeamEvidenceBucketName'].OutputValue | [0]" \
    --output text 2>/dev/null | grep -v '^None$' || true)
fi

if [ -z "$BUCKET" ] || [ "$BUCKET" = "None" ]; then
  echo
  echo "No team evidence bucket found (set TEAM_EVIDENCE_BUCKET, or ask your"
  echo "facilitator whether this event provisions one). Your submission is"
  echo "safe at $LOCAL_ZIP — copy it out of the account yourself before the"
  echo "event ends."
  exit 0
fi

KEY="submissions/${TEAM}/${ZIP_NAME}"
echo
echo "uploading to s3://${BUCKET}/${KEY} ..."
if ! aws s3 cp "$LOCAL_ZIP" "s3://${BUCKET}/${KEY}" --only-show-errors; then
  echo "upload failed — your zip is still at $LOCAL_ZIP; copy it out yourself before the event ends." >&2
  exit 1
fi

URL=$(aws s3 presign "s3://${BUCKET}/${KEY}" --expires-in 604800)
echo
echo "uploaded. Presigned URL (short-lived, tied to this IDE session):"
echo "  $URL"
echo
echo "Local copy kept at $LOCAL_ZIP — the account is torn down at the end of"
echo "the event, so download this from the bucket (or copy the local file"
echo "out) before then."
