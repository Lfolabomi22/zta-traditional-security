# Connecting Cordon to AWS — full process

This is the actual sequence to take the app from your machine to a running
AWS instance, using the artifacts in this `deploy/` folder. No steps are
skipped or hand-waved — every command below is real.

## What "connect to AWS" means here

Three separate things people mean by this, all covered:

1. **Provisioning** — creating the EC2 instance, security group, and IAM role that let the app run in your AWS account. → CloudFormation template.
2. **Getting the code onto AWS** — pushing your local files to the running instance. → `deploy.sh`.
3. **Observability link-back** — the app's audit log flowing into CloudWatch so you can query decisions from AWS, not just from the instance's disk. → CloudWatch agent config baked into the template's user-data.

## Prerequisites (do these once)

1. **AWS account** with billing enabled (a t3.micro is eligible for the free tier if your account is new).
2. **AWS CLI v2** installed locally: `aws --version`. If missing, install from AWS's docs for your OS.
3. **Configure credentials:**
   ```bash
   aws configure
   ```
   This asks for an Access Key ID, Secret Access Key, default region, and output format. Get the keys from **IAM → Users → your user → Security credentials → Create access key** in the AWS Console. Don't use your root account's keys — create an IAM user with `AdministratorAccess` (or a scoped policy covering EC2/IAM/CloudFormation/CloudWatch) for this.
4. **An EC2 key pair** for SSH:
   ```bash
   aws ec2 create-key-pair --key-name cordon-key --query "KeyMaterial" --output text > cordon-key.pem
   chmod 400 cordon-key.pem
   ```
   Keep `cordon-key.pem` in this `deploy/` folder — `deploy.sh` looks for it next to itself.
5. **Your public IP**, to lock SSH down to just you:
   ```bash
   curl -s ifconfig.me
   ```

## Step 1 — Provision + deploy in one command

```bash
cd deploy
chmod +x deploy.sh destroy.sh
./deploy.sh cordon-key <your-ip>/32
```

What this actually does, in order:
1. Runs `aws cloudformation deploy` with `cloudformation.yaml` — this is the real "link to AWS": it calls the CloudFormation API, which creates an IAM role (`CordonEC2Role`, scoped to CloudWatch Logs + SSM, nothing broader), a security group (SSH from your IP only, app port open), and an EC2 instance with that role attached via an instance profile.
2. Polls the stack until AWS reports the resources exist, then reads back the instance's public IP from the stack outputs.
3. Waits for SSH to come up (cloud-init takes ~30–60s after the instance shows "running").
4. `scp`s `zta_pdp.py`, `zta_pep.py`, `requirements.txt`, and `static/` onto the instance.
5. SSHes in, installs the Python dependencies, and restarts the `cordon.service` systemd unit that the instance's user-data script already created.

Takes roughly 2–3 minutes end to end for a fresh account.

## Step 2 — Verify it's actually live

```bash
curl http://<public-ip>:8000/health
```
Then open `http://<public-ip>:8000/console/` in a browser — this is the same console you tested locally, now running on an AWS-owned IP.

## Step 3 — Confirm the CloudWatch link

The instance's user-data already installed and configured the CloudWatch agent to tail `/var/log/cordon/audit.log` into log group `/cordon/pdp-decisions`. Check it from your machine:
```bash
aws logs tail /cordon/pdp-decisions --follow
```
Hit a few endpoints in the console and watch decisions appear here in near-real-time — this is the evidence stream for your thesis evaluation chapter. Query it in the console under **CloudWatch → Logs Insights**:
```
fields @timestamp, subject, resource, decision, trust_composite, rule
| filter decision = "DENY"
| sort @timestamp desc
```

## Step 4 — Making changes later

Edit `zta_pdp.py` / `zta_pep.py` locally, then just re-run:
```bash
./deploy.sh cordon-key <your-ip>/32
```
CloudFormation no-ops on the infrastructure (nothing to change), and the script re-ships the code and restarts the service. No manual SSH needed for routine updates.

## Step 5 — Tear down when you're done

This is not optional busywork — an idle t3.micro is cheap but not free, and leaving the security group/IAM role around is unnecessary exposure.
```bash
./destroy.sh
```

## What you can put in the thesis

- The CloudFormation template *is* your infrastructure-as-code artifact — screenshot or excerpt it as evidence of a repeatable, auditable deployment (a real ZTA claim: infrastructure defined declaratively, not clicked together by hand).
- The IAM role is deliberately least-privilege: `CloudWatchAgentServerPolicy` + `AmazonSSMManagedInstanceCore` + a scoped inline policy limited to `/cordon/*` log groups — no wildcard `*` resource access. Worth a sentence in your security-analysis section.
- The CloudWatch Logs Insights query above, run against real deployed traffic, is stronger evaluation evidence than a local pytest run — it shows the audit trail surviving the trip from application to cloud-native observability, which is the actual point of a cloud-native ZTA.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `deploy.sh` hangs on "Waiting for SSH" | Security group didn't open in time, or wrong CIDR | Check `aws ec2 describe-security-groups`, confirm your IP matches what you passed |
| Console loads but requests 502 | `cordon.service` failed to start | `ssh` in, `sudo journalctl -u cordon -n 50` |
| No CloudWatch logs appear | Agent config path wrong, or IAM role missing | `ssh` in, check `/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log` |
| `aws cloudformation deploy` fails with `AccessDenied` | Your IAM user lacks permission to create roles/instances | Use an account with `AdministratorAccess`, or ask whoever manages the AWS account |
