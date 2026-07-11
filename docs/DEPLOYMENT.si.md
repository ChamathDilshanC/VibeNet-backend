# VibeNet Backend — AWS EC2 Deployment මාර්ගෝපදේශය (සිංහල)

මේ guide එකෙන් VibeNet Go backend එක **AWS EC2 free-tier** instance එකක host කරන හැටි **step-by-step** පෙන්නනවා. මුල සිට පටන් ගන්නන්ට ලියලා තියෙනවා — server administration පිළිබඳ පෙර දැනුමක් අවශ්‍ය නෑ.

> 💡 **ඇයි EC2 (free tier)?** Backend එක real-time chat වලට **WebSocket** (දිගු කාලීන) connections පාවිච්චි කරන නිසා, එයාට **always-on** server එකක් ඕන. `t3.micro` / `t2.micro` instance එකක් **පළමු මාස 12ට free** (මාසෙකට 750 hours — එක instance එකක් 24/7 run කරන්න ඇති), always-on, free static IP එකක් එනවා, RDS එකේ same AWS account/VPC එකේම තියෙනවා.

> 🌐 **English version:** [DEPLOYMENT.md](./DEPLOYMENT.md)

---

## 🗺️ සමස්ත Plan එක (Overview)

```
1. EC2 instance එකක් launch කරන්න (t3.micro — free tier)
2. Security group එක config කරන්න (SSH 22 + backend port 8080)
3. SSH එකෙන් server එකට connect වෙන්න
4. Go install කරලා backend code එක ගන්න
5. .env file එක setup කරන්න (RDS / DynamoDB / IAM keys)
6. EC2 එකට RDS එකට යන්න permission දෙන්න (security group rule)
7. systemd service එකක් හදලා always-on කරන්න
8. (Optional) Domain + HTTPS — nginx එක්ක
```

---

## අන්තර්ගතය

1. [පෙර අවශ්‍යතා](#0-පෙර-අවශ්‍යතා)
2. [EC2 Instance එක Launch කරන්න](#1-ec2-instance-එක-launch-කරන්න)
3. [Security Group එක Config කරන්න](#2-security-group-එක-config-කරන්න)
4. [SSH එකෙන් Connect වෙන්න](#3-ssh-එකෙන්-connect-වෙන්න)
5. [Go Install කරලා Code එක ගන්න](#4-go-install-කරලා-code-එක-ගන්න)
6. [.env File එක Config කරන්න](#5-env-file-එක-config-කරන්න)
7. [EC2 → RDS Connectivity දෙන්න](#6-ec2--rds-connectivity-දෙන්න)
8. [systemd Service එකක් විදිහට Run කරන්න](#7-systemd-service-එකක්-විදිහට-run-කරන්න-always-on)
9. [Optional: Domain + HTTPS](#8-optional-domain--https-nginx-එක්ක)
10. [Deployment එක Verify කරන්න](#-deployment-එක-verify-කරන්න)
11. [Cost & Free-Tier කරුණු](#-cost--free-tier-කරුණු)
12. [Troubleshooting](#-troubleshooting)

---

## 0. පෙර අවශ්‍යතා

- **RDS PostgreSQL** සහ **DynamoDB** resources දැනටමත් හදලා තියෙන AWS account එකක් (බලන්න [`AWS_SETUP_GUIDE.md`](../../AWS_SETUP_GUIDE.md)).
- සම්පූර්ණ කරපු backend `.env` values (RDS endpoint, password, IAM keys, ආදිය).
- Backend source code එක git repository එකකට push කරලා (හෝ server එකට copy කරන්න ready).
- EC2, RDS, DynamoDB තුනටම **එකම region** — උදා: `ap-southeast-1` (Singapore).

---

## 1. EC2 Instance එක Launch කරන්න

1. AWS Console එකේ **EC2** service එක open කරන්න.
2. Region එක (උඩ-දකුණේ) RDS එකට match වෙනවද බලන්න — උදා: **Asia Pacific (Singapore) / ap-southeast-1**.
3. **Launch instance** click කරලා form එක පුරවන්න:

| Field | Value |
|-------|-------|
| **Name** | `vibenet-backend` |
| **AMI (OS image)** | **Ubuntu Server 24.04 LTS** — **Free tier eligible** label එක තියෙන එක |
| **Instance type** | **t3.micro** හෝ **t2.micro** — **Free tier eligible** label එක තියෙන එක |
| **Key pair** | **Create new key pair** → නම `vibenet-key`, type **RSA**, format **.pem** → **Download** |

4. **Network settings** යටතේ **Edit** click කරන්න:
   - **Allow SSH traffic from** → **My IP**
   - **Allow HTTPS traffic from the internet** → ✅
   - **Allow HTTP traffic from the internet** → ✅
5. **Configure storage:** default **8 GiB** හරි (free tier 30 GB දක්වා දෙනවා).
6. **Launch instance** click කරන්න.

> ⚠️ **වැදගත් — වැරදුනොත් මුදල් යන දේවල් 2ක්:**
> 1. **AMI** එකයි **Instance type** එකයි දෙකෙම **"Free tier eligible"** label එක තියෙන්න ඕන.
> 2. **Download කරපු `.pem` key file එක safe තැනක save කරන්න.** ඒක නැතුව SSH වෙන්න බෑ — අලුත් instance එකක් හදන්න වෙනවා.

---

## 2. Security Group එක Config කරන්න

Backend එක port **8080** එකේ listen කරනවා. ඒ port එක open කරන්න ඕන browsers/clients වලට API එක reach කරන්න.

1. ඔයාගෙ instance එක open කරන්න → **Security** tab → **security group** link එක click කරන්න.
2. **Inbound rules** → **Edit inbound rules** → **Add rule**:
   - **Type:** `Custom TCP`
   - **Port range:** `8080`
   - **Source:** **Anywhere-IPv4** (`0.0.0.0/0`) — public **API port** එකකට මේක හරි (database port එකකට වගේ නෙවෙයි).
3. SSH rule එක (port `22`) **My IP** විතරද කියලා confirm කරන්න.
4. **Save rules** click කරන්න.

> 📝 **NOTE:** Public API එකකට port `8080` internet එකට open කරන එක normal. පස්සෙ nginx + HTTPS (Step 8) දැම්මොත්, `8080` වහලා `443` විතරක් expose කරන්න පුළුවන්.

---

## 3. SSH එකෙන් Connect වෙන්න

`vibenet-key.pem` save කරපු folder එකේ terminal එකක් open කරන්න.

**Key එකේ permissions restrict කරන්න (macOS/Linux):**

```bash
chmod 400 vibenet-key.pem
```

**Connect වෙන්න** (`<EC2_PUBLIC_IP>` වෙනුවට console එකේ **Public IPv4 address** එක දාන්න):

```bash
ssh -i vibenet-key.pem ubuntu@<EC2_PUBLIC_IP>
```

**Windows (PowerShell)** — same command; permissions error එකක් ආවොත්:

```powershell
icacls vibenet-key.pem /inheritance:r /grant:r "$($env:USERNAME):(R)"
```

Host එක trust කරන්නද කියලා ඇහුවම `yes` type කරන්න. දැන් ඔයා server එකේ. 🎉

---

## 4. Go Install කරලා Code එක ගන්න

මේවා **EC2 server** එකේ (SSH එකෙන්) run කරන්න.

**System එක update කරලා Go + git install කරන්න:**

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y golang-go git
go version   # Go install වුණාද confirm කරන්න
```

> 💡 `apt` එකේ Go version එක backend එකේ `go.mod` එකට වඩා පරණ නම්, official tarball එකෙන් අලුත්ම එක install කරන්න:
> ```bash
> curl -LO https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
> sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
> echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
> go version
> ```

**Backend repository එක clone කරන්න:**

```bash
git clone https://github.com/ChamathDilshanC/VibeNet-backend.git
cd VibeNet-backend
```

> 🔐 Repo එක **private** නම්, GitHub **Personal Access Token** එකක් හදලා මෙහෙම clone කරන්න:
> `git clone https://<TOKEN>@github.com/ChamathDilshanC/VibeNet-backend.git`

**Binary එක build කරන්න:**

```bash
go build -o vibenet-api ./cmd/api
```

---

## 5. .env File එක Config කරන්න

Server එකේ `.env` file එක හදන්න:

```bash
nano .env
```

Production values (AWS_SETUP_GUIDE.md එකෙන්) paste කරන්න, උදාහරණයක්:

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

Save කරලා exit වෙන්න (`Ctrl+O`, `Enter`, `Ctrl+X`).

> ⚠️ **Local එකට වඩා production වෙනස්කම්:**
> - `APP_ENV=production`
> - `CORS_ALLOWED_ORIGINS` → deploy කරපු **frontend** URL(s), comma-separated.
> - `GOOGLE_REDIRECT_URL` → deploy කරපු **HTTPS backend** callback එක (Google Cloud Console එකේත් add කරන්න).

> 🔒 **Access keys වලට වඩා හොඳයි:** `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` server එකේ දානවා වෙනුවට, DynamoDB permissions තියෙන **IAM role** එකක් EC2 instance එකට attach කරන්න. AWS SDK එක ඒක automatic ගන්නවා, keys `.env` එකෙන් අයින් කරන්න පුළුවන්. බලන්න [Troubleshooting](#-troubleshooting).

---

## 6. EC2 → RDS Connectivity දෙන්න

ඔයාගෙ RDS security group එක දැන් **home IP** විතරයි allow කරන්නෙ. EC2 server එකේ IP එක වෙනස්, ඒ නිසා ඒකටත් permission දෙන්න ඕන.

**Recommended (security-group-to-security-group):**

1. AWS Console එකේ **RDS** → ඔයාගෙ `vibenet-db` → **Connectivity & security** → DB එකේ **VPC security group** එක click කරන්න.
2. **Inbound rules** → **Edit inbound rules** → **Add rule**:
   - **Type:** `PostgreSQL` (port 5432 auto-fill වෙනවා)
   - **Source:** type කරලා **EC2 instance එකේ security group** එක select කරන්න (උදා: `vibenet-backend` එකේ SG).
3. **Save rules**.

මේකෙන් backend එකට RDS එකට internal network එකෙන් reach කරන්න පුළුවන් — database එක public internet එකට expose කරන්නෙ නැතුව.

---

## 7. systemd Service එකක් විදිහට Run කරන්න (Always-On)

`./vibenet-api` manually run කරොත් SSH වහද්දී නවතිනවා. **systemd service** එකක් 24/7 run කරනවා, crash හෝ reboot වෙද්දී restart කරනවා.

**Service file එක හදන්න:**

```bash
sudo nano /etc/systemd/system/vibenet.service
```

මේක paste කරන්න:

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

Save කරලා exit වෙලා, enable කරලා start කරන්න:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vibenet
sudo systemctl start vibenet
sudo systemctl status vibenet   # "active (running)" පෙන්නන්න ඕන
```

**Logs බලන්න:**

```bash
sudo journalctl -u vibenet -f
```

දැන් backend එක `http://<EC2_PUBLIC_IP>:8080` එකේ reach කරන්න පුළුවන්.

---

## 8. Optional: Domain + HTTPS (nginx එක්ක)

Raw IP + port වෙනුවට production URL එකකට (`https://api.yourdomain.com`):

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

**nginx reverse proxy එකක් හදන්න** (`sudo nano /etc/nginx/sites-available/vibenet`):

```nginx
server {
    listen 80;
    server_name api.yourdomain.com;

    # Avatar uploads 5 MiB දක්වා multipart bodies (internal/api/handler.go එකේ
    # maxAvatarBytes බලන්න). nginx default cap එක 1 MB නිසා, මේක නැතුව හරි
    # photos 413 එකක් එක්ක Go එකට යන්න කලින්ම reject වෙනවා — ඒ 413 error page
    # එකේ CORS headers නෑ, ඒ නිසා browser එක ඒක CORS error එකක් විදියට පෙන්නනවා.
    # මේක Go limit එකට සමානව හෝ වැඩියෙන් තියන්න.
    client_max_body_size 6m;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;      # WebSocket වලට අවශ්‍යයි
        proxy_set_header Connection "upgrade";        # WebSocket වලට අවශ්‍යයි
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable කරලා free TLS certificate එකක් ගන්න:

```bash
sudo ln -s /etc/nginx/sites-available/vibenet /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d api.yourdomain.com
```

මුලින්ම domain එකේ **A record** එක EC2 public IP එකට point කරන්න. ඊට පස්සෙ security group එකේ port `8080` වහලා, `80`/`443` විතරක් තියන්න.

> 🔌 **WebSocket satahan:** උඩ තියෙන `proxy_set_header Upgrade`/`Connection` lines **අත්‍යවශ්‍යයි** — ඒවා නැතුව `/ws` chat endpoint එක nginx පිටිපස්සෙ වැඩ කරන්නෙ නෑ.

> 📤 **Upload-size satahan:** avatar uploads වලට `client_max_body_size 6m;` line එක **අත්‍යවශ්‍යයි**. nginx default 1 MB limit එකෙන් ලොකු multipart bodies `413` එකක් එක්ක reject කරනවා, ඒ error page එකේ CORS headers නැති නිසා browser එකේ CORS error එකක් විදියට පෙන්නනවා. දැනටමත් nginx run වෙනවා නම්, මේ line එක තියෙන `/etc/nginx/sites-available/vibenet` එකට add කරලා `sudo nginx -t && sudo systemctl reload nginx` run කරන්න.

---

## ✅ Deployment එක Verify කරන්න

ඔයාගෙ **local machine** එකෙන් deep health check එක hit කරන්න:

```bash
curl -s http://<EC2_PUBLIC_IP>:8080/health | jq
```

Expected — දෙකම reach වෙනවා:

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

`postgres` එක `down` නම් → [Step 6](#6-ec2--rds-connectivity-දෙන්න) බලන්න. `dynamodb` එක `down` නම් → IAM keys/role එකයි `AWS_REGION` එකයි check කරන්න.

---

## 💰 Cost & Free-Tier කරුණු

| Resource | Free-tier දීමනාව | මාස 12න් පස්සෙ |
|----------|-----------------|---------------|
| EC2 `t3.micro`/`t2.micro` | මාසෙකට 750 hrs, මාස 12ට (එක 24/7 instance) | ~$7–9/මාසෙ |
| EBS storage (8–30 GB) | 30 GB free, මාස 12ට | ~$0.10/GB-මාසෙ |
| Data transfer out | මාසෙකට 100 GB free | පස්සෙ $0.09/GB |
| Elastic IP | Instance එක running නම් **free** | Attach නැත්නම් charge |

> ⚠️ **හදිසි bill වළක්වන්න:**
> - EC2 **සහ** RDS දෙකෙම free tier **මාස 12න්** ඉවර — ඊට පස්සෙ දෙකම එකට ~**$15–20/මාසෙ**.
> - ඕන නැති වෙලාවෙ instance එක **Stop / Terminate** කරන්න.
> - **Attach නොකළ Elastic IP** එකක් තියන්න එපා — bill වෙනවා.
> - **AWS Budgets** alert එකක් දාන්න (උදා: $1 එකේදී notify) — නොහිතූ දේවල් catch කරන්න.

---

## 🔧 Troubleshooting

| ලක්ෂණය | හේතුව & විසඳුම |
|--------|---------------|
| SSH `Permission denied (publickey)` | වැරදි user (Ubuntu AMIs වලට `ubuntu`) හෝ key perms — `chmod 400 vibenet-key.pem`. |
| `:8080` එකට `curl` timeout | Security group එකේ port `8080` inbound rule එක නෑ ([Step 2](#2-security-group-එක-config-කරන්න)). |
| `/health` → `postgres: down` | RDS security group එක EC2 SG එකට allow කරන්නෙ නෑ ([Step 6](#6-ec2--rds-connectivity-දෙන්න)); හෝ වැරදි `POSTGRES_HOST`. |
| `/health` → `dynamodb: down` | වැරදි IAM keys, වැරදි `AWS_REGION`, හෝ table name mismatch. |
| Service start වෙන්නෙ නෑ | `sudo journalctl -u vibenet -f` එකෙන් error එක බලන්න; service file එකේ `.env` path එක check කරන්න. |
| Go build එකේ memory ඉවර | `t3.micro` එකේ 1 GB RAM — swap දාන්න: `sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile`. |

**Access keys වෙනුවට IAM role එකක් (recommended):**

1. **IAM** → **Roles** → **Create role** → **AWS service** → **EC2**.
2. **AmazonDynamoDBFullAccess** attach කරන්න (හෝ `vibenet-messages` වලට scoped least-privilege policy එකක්).
3. නම `vibenet-backend-role` කියලා create කරන්න.
4. **EC2** → instance → **Actions** → **Security** → **Modify IAM role** → `vibenet-backend-role` attach කරන්න.
5. `.env` එකෙන් `AWS_ACCESS_KEY_ID` සහ `AWS_SECRET_ACCESS_KEY` අයින් කරලා service එක restart කරන්න. දැන් SDK එක role එක automatic පාවිච්චි කරනවා.

---

## 📋 Deployment Checklist

- [ ] EC2 `t3.micro`/`t2.micro` launch කළා (Free tier eligible)
- [ ] `.pem` key එක safe තැනක save කළා
- [ ] Security group: port `8080` open, SSH `22` My IP වලට restrict
- [ ] Go install, code clone, binary build
- [ ] `.env` production values එක්ක config (`APP_ENV=production`)
- [ ] RDS security group එක EC2 security group එකට allow
- [ ] `vibenet.service` running (`systemctl status vibenet` → active)
- [ ] `http://<EC2_PUBLIC_IP>:8080/health` → `status: ok`
- [ ] (Optional) Domain + HTTPS — nginx + certbot
- [ ] AWS Budgets alert config කළා
