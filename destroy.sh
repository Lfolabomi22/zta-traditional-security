#!/usr/bin/env bash
# destroy.sh — tears down everything deploy.sh created. Run this when you're
# done demoing so the instance and IAM role don't keep costing/lingering.
set -euo pipefail
STACK_NAME="cordon-zta-demo"
REGION="${AWS_REGION:-us-east-1}"

echo "==> Deleting stack $STACK_NAME"
aws cloudformation delete-stack --stack-name "$STACK_NAME" --region "$REGION"
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region "$REGION"
echo "==> Stack deleted."
