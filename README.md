# 🛡️ SOCify - SOC Simulation Platform

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green)
![Security](https://img.shields.io/badge/Security-Simulation-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📌 Overview
**SOCify** is a comprehensive and advanced **Security Operations Center (SOC)** simulation platform. It is designed to provide a realistic, safe environment for security analysts to practice threat detection, analysis, and response without risking actual infrastructure.

### 💡 The Problem & Solution
* **The Problem:** The lack of practical, hands-on training environments for SOC analysts, with most education relying heavily on theory.
* **The Solution:** SOCify offers an isolated sandbox environment that simulates real-world attacks (e.g., DDoS, SQLi) and allows users to analyze logs and take action.

---

## ✨ Key Features

### 1. 🔐 Advanced Role-Based Access Control (RBAC)
* **Security Analyst:** Monitor events, analyze threats, and add investigation notes.
* **SOC Manager:** Manage detection rules, oversee team performance, and view reports.
* **System Admin:** Full system control and database management.

### 2. 🧪 Simulation Lab
The platform generates realistic attack scenarios for training purposes:
* 🕷️ **Web Attacks:** SQL Injection, XSS, CSRF, Directory Traversal.
* 🌐 **Network Attacks:** DDoS, DoS, Port Scanning.
* 🔑 **Auth Attacks:** Brute Force, Credential Stuffing.
* 🎣 **Social Eng:** Phishing simulation.

### 3. ⚙️ Rules Engine & Automation
* Custom detection rules creation.
* Automated alerting based on thresholds.
* Incident severity classification (Critical, High, Medium, Low).

---

## 🛠️ Tech Stack

### Backend
* **Language:** Python 3.x
* **Framework:** Flask
* **Database:** SQLite (SQLAlchemy)
* **Security:** Bcrypt (Hashing), CSRF Protection

### Frontend
* **Design:** HTML5, CSS3 (Custom Dashboard Design)
* **Interactivity:** JavaScript (ES6+)
* **Visualization:** Real-time Logs & Charts

---

## 📂 Project Structure

```text
SOCify/
├── app.py             # Main Application (Flask)
├── create_db.py       # Database Initialization Script
├── socify.db          # SQLite Database
├── requirements.txt   # Python Dependencies
├── templates/         # HTML Templates (Dashboard, Lab, Login...)
├── static/            # Static Assets (CSS, JS, Images)
└── README.md          # Project Documentation

```

---

## 🚀 Installation Guide

Follow these steps to run the project locally:

1. **Clone the Repository:**
```bash
git clone [https://github.com/YourUsername/SOCify-Project.git](https://github.com/YourUsername/SOCify-Project.git)
cd SOCify-Project

```


2. **Install Dependencies:**
```bash
pip install -r requirements.txt

```


3. **Initialize Database:**
```bash
python init_db.py

```


*(This script creates the tables and populates them with demo data)*
4. **Run the Server:**
```bash
python run.py

```


5. **Access the Platform:**
Open your browser and navigate to: `http://localhost:5000`

---

## 🔑 Demo Credentials

| Role | Email | Password |
| --- | --- | --- |
| **Admin** | `admin@socify.local` | `admin123` |
| **Manager** | `manager@socify.local` | `password123` |
| **Analyst** | `analyst1@socify.local` | `password123` |

> ⚠️ **Note:** These credentials are for demonstration purposes only. Please change them in a production environment.

---

## 🆘 Support & Issues

If you encounter any bugs or issues, please feel free to open an **Issue** here on GitHub.

---

## 👨‍💻 Author

Developed by **Mohammad Alqarni**.

* **LinkedIn:** [Mohammad Alqarni](https://www.linkedin.com/in/mohammad-alqarni-sec?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=ios_app)
* **Email:** mohammad.aqarni.10@gmail.com

All Rights Reserved © 2025 SOCify