# VibeNet Backend — AWS EC2 Deployment Guide

This guide walks you **step-by-step** through hosting the VibeNet Go backend on an **AWS EC2 free-tier** instance. It is written for beginners — no prior server-administration experience required.

> 💡 **Why EC2 (free tier)?** The backend uses long-lived **WebSocket** connections for real-time chat, so it needs an **always-on** server. A `t3.micro` / `t2.micro` instance is **free for the first 12 months** (750 hours/month — enough for one instance running 24/7), stays always-on, gets a free static IP, and lives in the same AWS account/VPC as your RDS database.

> 🇱🇰 **සිංහල version:** [DEPLOYMENT.si.md](./DEPLOYMENT.si.md)

---

## 🗺️ Overview

```
1. Launch an EC2 instance (t3.micro — free tier)
2. Configure the security group (SSH 22 + backend port 8080)
3. Connect to the server over SSH
4. Install Go and pull the backend code
5. Set up the .env file (RDS / DynamoDB / IAM keys)
6. Allow the EC2 instance to reach RDS (security group rule)
7. Create a systemd service so the backend stays always-on
8. (Optional) Add a domain + HTTPS with nginx
```

---

## Table of Contents

1. [Prerequisites](#0-prerequisites)
2. [Launch the EC2 Instance](#1-launch-the-ec2-instance)
3. [Configure the Security Group](#2-configure-the-security-group)
4. [Connect over SSH](#3-connect-over-ssh)
5. [Install Go & Pull the Code](#4-install-go--pull-the-code)
6. [Configure the `.env` File](#5-configure-the-env-file)
7. [Allow EC2 → RDS Connectivity](#6-allow-ec2--rds-connectivity)
8. [Run as a systemd Service (Always-On)](#7-run-as-a-systemd-service-always-on)
9. [Optional: Domain + HTTPS with nginx](#8-optional-domain--https-with-nginx)
10. [Verify the Deployment](#-verify-the-deployment)
11. [Cost & Free-Tier Notes](#-cost--free-tier-notes)
12. [Troubleshooting](#-troubleshooting)

---

## 0. Prerequisites

- An AWS account with the **RDS PostgreSQL** and **DynamoDB** resources already created (see [`AWS_SETUP_GUIDE.md`](../../AWS_SETUP_GUIDE.md)).
- Your completed backend `.env` values (RDS endpoint, password, IAM keys, etc.).
- The backend source code pushed to a git repository (or ready to copy to the server).
- **Same region** for EC2, RDS, and DynamoDB — e.g. `ap-southeast-1` (Singapore).

---

## 1. Launch the EC2 Instance

1. In the AWS Console, open the **EC2** service.
2. Confirm the region (top-right) matches your RDS, e.g. **Asia Pacific (Singapore) / ap-southeast-1**.
3. Click **Launch instance** and fill in the form:

| Field | Value |
|-------|-------|
| **Name** | `vibenet-backend` |
| **AMI (OS image)** | **Ubuntu Server 24.04 LTS** — the one labelled **Free tier eligible** |
| **Instance type** | **t3.micro** or **t2.micro** — the one labelled **Free tier eligible** |
| **Key pair** | **Create new key pair** → name `vibenet-key`, type **RSA**, format **.pem** → **Download** |

4. Under **Network settings** click **Edit**:
   - **Allow SSH traffic from** → **My IP**
   - **Allow HTTPS traffic from the internet** → ✅
   - **Allow HTTP traffic from the internet** → ✅
5. **Configure storage:** the default **8 GiB** is fine (free tier includes up to 30 GB).
6. Click **Launch instance**.

> ⚠️ **IMPORTANT — two things that cost money if you get them wrong:**
> 1. Both the **AMI** and the **Instance type** must show the **"Free tier eligible"** label.
> 2. **Save the downloaded `.pem` key file** somewhere safe. Without it you cannot SSH in, and you'd have to recreate the instance.

---

## 2. Configure the Security Group

The backend listens on port **8080**. You must open that port so browsers/clients can reach the API.

1. Open your instance → **Security** tab → click the **security group** link.
2. **Inbound rules** → **Edit inbound rules** → **Add rule**:
   - **Type:** `Custom TCP`
   - **Port range:** `8080`
   - **Source:** **Anywhere-IPv4** (`0.0.0.0/0`) — this is fine for a **public API port** (unlike a database port).
3. Confirm the SSH rule (port `22`) is set to **My IP** only.
4. Click **Save rules**.

> 📝 **NOTE:** Opening `8080` to the internet is expected for a public API. Later, if you add nginx + HTTPS (Step 8), you can close `8080` and expose only `443` instead.

---

## 3. Connect over SSH

Open a terminal in the folder where you saved `vibenet-key.pem`.

**Restrict the key's permissions (macOS/Linux):**

```bash
chmod 400 vibenet-key.pem
```

**Connect** (replace `<EC2_PUBLIC_IP>` with the instance's **Public IPv4 address** from the console):

```bash
ssh -i vibenet-key.pem ubuntu@<EC2_PUBLIC_IP>
```

**Windows (PowerShell)** uses the same command; if you hit a permissions error, run:

```powershell
icacls vibenet-key.pem /inheritance:r /grant:r "$($env:USERNAME):(R)"
```

Type `yes` when asked to trust the host. You are now on the server.

---

## 4. Install Go & Pull the Code

Run these on the **EC2 server** (over SSH).

**Update the system and install Go + git:**

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y golang-go git
go version   # confirm Go is installed
```

> 💡 If `apt`'s Go version is older than the backend's `go.mod` requires, install the latest from the official tarball instead:
> ```bash
> curl -LO https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
> sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
> echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
> go version
> ```

**Clone the backend repository:**

```bash
git clone https://github.com/ChamathDilshanC/VibeNet-backend.git
cd VibeNet-backend
```

> 🔐 If the repo is **private**, generate a GitHub **Personal Access Token** and clone with:
> `git clone https://<TOKEN>@github.com/ChamathDilshanC/VibeNet-backend.git`

**Build the binary:**

```bash
go build -o vibenet-api ./cmd/api
```

---

## 5. Configure the `.env` File

Create the `.env` file on the server:

```bash
nano .env
```

Paste your production values (from `AWS_SETUP_GUIDE.md`), for example:

```dotenv
APP_ENV=production
APP_PORT=8080
APP_VERSION=1.0.0
CORS_ALLOWED_ORIGINS=https://your-frontend-domain.com

JWT_SECRET=your_production_jwt_secret
JWT_EXPIRY_HOURS=72

GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URL=https://your-backend-domain.com/api/auth/google/callback

POSTGRES_HOST=vibenet-db.xxxxx.ap-southeast-1.rds.amazonaws.com
POSTGRES_PORT=5432
POSTGRES_USER=vibenet_admin
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=vibenet
POSTGRES_SSLMODE=require

AWS_REGION=ap-southeast-1
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
DYNAMODB_MESSAGES_TABLE=vibenet-messages
```

Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).

> ⚠️ **Production changes vs local:**
> - `APP_ENV=production`
> - `CORS_ALLOWED_ORIGINS` → your deployed **frontend** URL(s), comma-separated.
> - `GOOGLE_REDIRECT_URL` → your deployed **HTTPS backend** callback (also add it in Google Cloud Console).

> 🔒 **Better than access keys:** instead of putting `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` on the server, attach an **IAM role** with DynamoDB permissions to the EC2 instance. The AWS SDK picks it up automatically and you can delete the keys from `.env`. See [Troubleshooting](#-troubleshooting).

---

## 6. Allow EC2 → RDS Connectivity

Your RDS security group currently only allows **your home IP**. The EC2 server has a different IP, so you must allow it too.

**Recommended (security-group-to-security-group):**

1. In the AWS Console open **RDS** → your `vibenet-db` → **Connectivity & security** → click the DB's **VPC security group**.
2. **Inbound rules** → **Edit inbound rules** → **Add rule**:
   - **Type:** `PostgreSQL` (port 5432 auto-fills)
   - **Source:** start typing and select the **EC2 instance's security group** (e.g. `vibenet-backend`'s SG).
3. **Save rules**.

This lets the backend reach RDS over the internal network without exposing the database to the public internet.

---

## 7. Run as a systemd Service (Always-On)

Running `./vibenet-api` manually stops when you close SSH. A **systemd service** keeps it running 24/7 and restarts it on crash or reboot.

**Create the service file:**

```bash
sudo nano /etc/systemd/system/vibenet.service
```

Paste:

```ini
[Unit]
Description=VibeNet Backend API
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/VibeNet-backend
ExecStart=/home/ubuntu/VibeNet-backend/vibenet-api
EnvironmentFile=/home/ubuntu/VibeNet-backend/.env
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Save and exit, then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vibenet
sudo systemctl start vibenet
sudo systemctl status vibenet   # should show "active (running)"
```

**View logs:**

```bash
sudo journalctl -u vibenet -f
```

The backend is now reachable at `http://<EC2_PUBLIC_IP>:8080`.

---

## 8. Optional: Domain + HTTPS with nginx

For a production URL (`https://api.yourdomain.com`) instead of a raw IP + port:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

**Create an nginx reverse proxy** (`sudo nano /etc/nginx/sites-available/vibenet`):

```nginx
server {
    listen 80;
    server_name api.yourdomain.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;      # required for WebSocket
        proxy_set_header Connection "upgrade";        # required for WebSocket
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable it and obtain a free TLS certificate:

```bash
sudo ln -s /etc/nginx/sites-available/vibenet /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d api.yourdomain.com
```

Point your domain's **A record** at the EC2 public IP first. After this, close port `8080` in the security group and keep only `80`/`443`.

> 🔌 **WebSocket note:** the `proxy_set_header Upgrade`/`Connection` lines above are **required** — without them the `/ws` chat endpoint will not work behind nginx.

---

## ✅ Verify the Deployment

From your **local machine**, hit the deep health check:

```bash
curl -s http://<EC2_PUBLIC_IP>:8080/health | jq
```

Expected — both dependencies reachable:

```json
{
  "status": "ok",
  "service": "vibenet-backend",
  "version": "1.0.0",
  "environment": "production",
  "services": {
    "postgres": { "status": "up", "latency_ms": 4 },
    "dynamodb": { "status": "up", "latency_ms": 12 }
  }
}
```

If `postgres` is `down`, re-check [Step 6](#6-allow-ec2--rds-connectivity). If `dynamodb` is `down`, check the IAM keys/role and `AWS_REGION`.

---

## 💰 Cost & Free-Tier Notes

| Resource | Free-tier allowance | After 12 months |
|----------|---------------------|-----------------|
| EC2 `t3.micro`/`t2.micro` | 750 hrs/month for 12 months (one 24/7 instance) | ~$7–9/month |
| EBS storage (8–30 GB) | 30 GB free for 12 months | ~$0.10/GB-month |
| Data transfer out | 100 GB/month free | $0.09/GB after |
| Elastic IP | Free **while attached to a running instance** | Charged if unattached |

> ⚠️ **Avoid surprise bills:**
> - Both EC2 **and** RDS free tiers end after **12 months** — after that the pair costs roughly **$15–20/month**.
> - **Stop or terminate** the instance when you no longer need it.
> - Don't leave an **unattached Elastic IP** — it's billed.
> - Set up an **AWS Budgets** alert (e.g. notify at $1) to catch anything unexpected.

---

## 🔧 Troubleshooting

| Symptom | Likely cause & fix |
|---------|-------------------|
| SSH `Permission denied (publickey)` | Wrong user (`ubuntu` for Ubuntu AMIs) or key perms — run `chmod 400 vibenet-key.pem`. |
| `curl` to `:8080` times out | Security group missing the port `8080` inbound rule ([Step 2](#2-configure-the-security-group)). |
| `/health` → `postgres: down` | RDS security group doesn't allow the EC2 SG ([Step 6](#6-allow-ec2--rds-connectivity)); or wrong `POSTGRES_HOST`. |
| `/health` → `dynamodb: down` | Bad IAM keys, wrong `AWS_REGION`, or table name mismatch. |
| Service won't start | `sudo journalctl -u vibenet -f` to read the error; check `.env` path in the service file. |
| Go build runs out of memory | `t3.micro` has 1 GB RAM — add swap: `sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile`. |

**Use an IAM role instead of access keys (recommended):**

1. **IAM** → **Roles** → **Create role** → **AWS service** → **EC2**.
2. Attach **AmazonDynamoDBFullAccess** (or a least-privilege policy scoped to `vibenet-messages`).
3. Name it `vibenet-backend-role` and create it.
4. **EC2** → your instance → **Actions** → **Security** → **Modify IAM role** → attach `vibenet-backend-role`.
5. Remove `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from `.env` and restart the service. The AWS SDK now uses the role automatically.

---

## 📋 Deployment Checklist

- [ ] EC2 `t3.micro`/`t2.micro` launched (Free tier eligible)
- [ ] `.pem` key saved securely
- [ ] Security group: port `8080` open, SSH `22` restricted to My IP
- [ ] Go installed, code cloned, binary built
- [ ] `.env` configured with production values (`APP_ENV=production`)
- [ ] RDS security group allows the EC2 security group
- [ ] `vibenet.service` running (`systemctl status vibenet` → active)
- [ ] `http://<EC2_PUBLIC_IP>:8080/health` returns `status: ok`
- [ ] (Optional) Domain + HTTPS via nginx + certbot
- [ ] AWS Budgets alert configured
