# 🌐 Complete Deployment Guide: Threat Intelligence AI Platform

**Course Code:** 23CSE528 — NoSQL Databases using MongoDB  
**Author:** Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)  
**Repository:** [https://github.com/ay1371872/mangoDB-and-nosql](https://github.com/ay1371872/mangoDB-and-nosql)  

---

## ⚡ 3 Ways to Deploy Your Project to the Cloud

| Method | Hosting Provider | Cost | Time | Best For |
|---|---|---|---|---|
| **Method 1** | **Streamlit Community Cloud** | 100% Free | 2 mins | **College Presentation & Viva (Instant public link: `https://...streamlit.app`)** |
| **Method 2** | **Render.com (Docker)** | 100% Free | 5 mins | **Deploying the FastAPI Backend + Docker container** |
| **Method 3** | **Cloud VM (AWS EC2 / DigitalOcean)** | Free Tier / $5/mo | 5 mins | **Full-Stack Docker Compose (MongoDB 7.0 + Backend + UI)** |

---

## 🚀 Method 1: Streamlit Community Cloud (Recommended for College Viva)

This gives you a permanent, secure public link (`https://<your-app-name>.streamlit.app`) that your lecturer, faculty, or external examiner can open from anywhere on their phone or laptop.

### Step-by-Step Instructions:
1. Open your browser and go to: **[https://share.streamlit.io](https://share.streamlit.io)**
2. Click **"Continue with GitHub"** and sign in with your GitHub account (`ay1371872`).
3. Click the **"New app"** button.
4. Fill in these 3 fields:
   - **Repository:** `ay1371872/mangoDB-and-nosql`
   - **Branch:** `main`
   - **Main file path:** `llm/streamlit_app.py`
   - **App URL (optional):** Choose a custom subdomain (e.g., `ayush-threat-intel-mongodb`)
5. Click **"Deploy!"**

*Within 60–90 seconds, Streamlit Cloud builds your dependencies from `requirements.txt` and publishes your live interactive application.*

---

## ☁️ Method 2: Render.com (Full-Stack Docker Deployment)

Render allows you to deploy containerized web services directly from your GitHub repository for free.

### Step-by-Step Instructions:
1. Sign up at **[https://render.com](https://render.com)** (sign in with GitHub).
2. Click **"New +"** ➔ **"Web Service"**.
3. Connect your repository: `ay1371872/mangoDB-and-nosql`.
4. Configure service settings:
   - **Name:** `threat-intel-api`
   - **Language:** `Docker`
   - **Dockerfile Path:** `llm/Dockerfile`
   - **Docker Context Directory:** `llm`
   - **Instance Type:** `Free`
5. Under **Environment Variables**, add:
   - `MONGO_URI`: `mongodb+srv://...` (Your MongoDB Atlas connection string)
   - `LLM_BACKEND`: `local_slm`
6. Click **"Create Web Service"**.

---

## 🏢 Method 3: Cloud VPS / AWS EC2 / DigitalOcean (Using Docker Compose)

If deploying to a cloud virtual machine (Ubuntu / Debian / Amazon Linux):

### Step 1: Connect to your Cloud Server via SSH
```bash
ssh ubuntu@your-server-ip
```

### Step 2: Install Docker & Docker Compose (if not already installed)
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

### Step 3: Clone Your GitHub Repository
```bash
git clone https://github.com/ay1371872/mangoDB-and-nosql.git
cd mangoDB-and-nosql/llm
```

### Step 4: Launch Full-Stack in Background
```bash
sudo docker compose up --build -d
```

### Step 5: Configure Firewall / Security Group
Ensure incoming traffic is allowed on:
- Port `8501` (Streamlit Web Dashboard)
- Port `8000` (FastAPI Swagger Docs)

Access via: `http://your-server-ip:8501`

---

## 🍃 Connecting MongoDB Atlas Cloud Database (Exercise 2)

By default, the application runs with an intelligent in-memory engine when offline, but you can connect to a production MongoDB Atlas cloud cluster:

1. Go to **[https://www.mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas)** and sign in.
2. Create a free **M0 Shared Cluster**.
3. Under **Database Access**, create a user (e.g., `ayush_admin`).
4. Under **Network Access**, click **Add IP Address** ➔ **Allow Access from Anywhere (`0.0.0.0/0`)**.
5. Click **Connect** ➔ **Drivers (Python)** ➔ copy the connection URI:
   ```text
   mongodb+srv://ayush_admin:<password>@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority
   ```
6. In `llm/.env`, update:
   ```bash
   MONGO_URI=mongodb+srv://ayush_admin:<password>@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority
   ```

---
*Created by: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)*
