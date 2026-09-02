#!/usr/bin/env bash
# deploy.sh — provisions the EC2 stack (if not already up), ships the app
# code, and starts the Cordon service. Requires AWS CLI v2 configured with
# credentials that can create IAM roles, security groups, and EC2 instances.
#
# Usage:
#   ./deploy.sh <key-pair-name> <your-ip>/32
#
# Re-running is safe: CloudFormation no-ops if the stack already matches,
# and the code push always overwrites with the latest local copy.

set -euo pipefail

STACK_NAME="cordon-zta-demo"
REGION="${AWS_REGION:-us-east-1}"
KEY_NAME="${1:?Usage: ./deploy.sh <key-pair-name> <your-ip-cidr>}"
SSH_CIDR="${2:?Usage: ./deploy.sh <key-pair-name> <your-ip-cidr>}"

echo "==> Deploying CloudFormation stack ($STACK_NAME) in $REGION"
aws cloudformation deploy \
  --template-file cloudformation.yaml \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides KeyName="$KEY_NAME" SSHLocation="$SSH_CIDR"

echo "==> Fetching outputs"
PUBLIC_IP=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='PublicIp'].OutputValue" \
  --output text)
echo "    instance public IP: $PUBLIC_IP"

echo "==> Waiting for SSH to come up"
until ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
  -i "${KEY_NAME}.pem" ubuntu@"$PUBLIC_IP" "echo ready" 2>/dev/null; do
  sleep 5
done

echo "==> Shipping application code"
scp -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" -r \
  ../zta_pdp.py ../zta_pep.py ../requirements.txt ../static \
  ubuntu@"$PUBLIC_IP":/home/ubuntu/zta_app/

echo "==> Installing dependencies and (re)starting the service"
ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" ubuntu@"$PUBLIC_IP" '
  sudo pip install --break-system-packages -r /home/ubuntu/zta_app/requirements.txt
  sudo systemctl restart cordon.service
  sleep 1
  sudo systemctl status cordon.service --no-pager | head -5
'

echo ""
echo "==> Done. Console:   http://${PUBLIC_IP}:8000/console/"
echo "==> Health check:    curl http://${PUBLIC_IP}:8000/health"
echo "==> Live logs:       ssh -i ${KEY_NAME}.pem ubuntu@${PUBLIC_IP} 'tail -f /var/log/cordon/audit.log'"
echo "==> CloudWatch:      log group /cordon/pdp-decisions"
