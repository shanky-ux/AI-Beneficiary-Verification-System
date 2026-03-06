# SS Fraud Prevention System — Local Setup Guide

## ✅ Quick Start (3 commands)

```bash
# 1. Navigate to the standalone directory
cd ss-fraud-system/standalone

# 2. Start both servers
node start.js

# 3. Open your browser
#    → http://localhost:3000
```

---

## 🔑 Login Credentials

| Role     | Email                      | Password       |
|----------|----------------------------|----------------|
| **Admin**    | `admin@ssfps.gov.in`   | `Admin@123456` |
| **Operator** | `operator@ssfps.gov.in`| `Operator@123` |

---

## 🌐 URLs

| Service  | URL                              |
|----------|----------------------------------|
| Website  | http://localhost:3000            |
| API      | http://localhost:4000/api/v1     |
| Health   | http://localhost:4000/health     |

---

## 📁 Project Structure (Standalone)

```
standalone/
├── start.js              ← Master launcher (run this!)
├── backend/
│   ├── server.js         ← Full REST API (zero dependencies)
│   ├── .env              ← Environment configuration
│   └── data/             ← JSON database files (auto-created)
│       ├── users.json
│       ├── beneficiaries.json
│       ├── fraudCases.json
│       ├── payments.json
│       ├── auditLogs.json
│       └── notifications.json
└── frontend/
    ├── index.html        ← Complete React SPA
    └── serve.js          ← Static file server
```

---

## ⚙️ Requirements

- **Node.js ≥ 14** (any recent version works)
- No npm install needed
- No PostgreSQL needed
- No Docker needed

---

## 🚀 Manual Start (separate terminals)

If you want to run backend and frontend separately:

**Terminal 1 — Backend:**
```bash
cd ss-fraud-system/standalone/backend
node server.js
# → http://localhost:4000
```

**Terminal 2 — Frontend:**
```bash
cd ss-fraud-system/standalone/frontend
node serve.js
# → http://localhost:3000
```

---

## 🔧 Configuration

Edit `backend/.env` to change settings:

```env
PORT=4000                    # Backend port
FRONTEND_ORIGIN=http://localhost:3000   # Frontend URL for CORS
JWT_SECRET=...               # Change in production!
FIELD_ENCRYPTION_KEY=...     # 64 hex chars (32 bytes AES key)
FRAUD_AUTO_STOP_THRESHOLD=75 # Score ≥ 75 → auto-stop payment
FRAUD_FLAG_THRESHOLD=50      # Score ≥ 50 → flag as fraud
```

---

## 📊 Features

### Dashboard
- Live stats: total beneficiaries, active payments, fraud cases, blocked payments
- 6-month fraud trend area chart
- Beneficiary status bar chart
- Severity distribution grid

### Beneficiary Management
- Full CRUD (Create, Read, Update, Delete)
- Paginated data table with search and status filter
- Inline fraud check button
- Detail panel with verification actions

### Fraud Cases
- Real-time fraud scoring (0–100)
- 6 rule-based detectors:
  - Death registry confirmation (+40)
  - Payment during suspension (+30)
  - Life certificate expired/missing (+10–25)
  - Aadhaar unverified (+20)
  - Verification overdue (+5–15)
  - Age anomaly (>100 or <60) (+8–10)
- Auto payment stop at score ≥ 75
- Case review panel with status updates

### Verifications (Mock APIs)
- Aadhaar OTP authentication (UIDAI mock)
- Death registry check (CRS mock)
- Life certificate status (Jeevan Pramaan mock)

### Analytics
- Monthly fraud trend charts
- Beneficiary status breakdown with progress bars
- Financial impact metrics (savings from stopped payments)

### Audit Logs (Admin only)
- Complete immutable action log
- Filter by action type
- User and beneficiary attribution

### Notifications
- Real-time in-app alerts
- Fraud alerts auto-created when payments are stopped
- Mark read / mark all read

---

## 🔒 Security Features

- JWT authentication (8h access + 7d refresh tokens)
- Role-based access control (ADMIN vs OPERATOR)
- AES-256-GCM field encryption for Aadhaar and bank account numbers
- Timing-safe password comparison (prevents enumeration)
- Rate limiting (100 req/15min, 10 login/15min)
- CORS restricted to frontend origin
- Aadhaar/bank numbers masked in all API responses
- Audit log on every mutating action

---

## 🗃️ Data Persistence

Data is stored in JSON files in `backend/data/`. 
To reset all data and re-seed: `rm -rf backend/data/ && node server.js`

---

## 🔗 API Reference

All endpoints: `http://localhost:4000/api/v1`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /auth/login | Public | Get JWT tokens |
| POST | /auth/refresh | Public | Refresh access token |
| GET | /auth/me | JWT | Current user |
| GET | /beneficiaries | JWT | List (paginated) |
| GET | /beneficiaries/stats | JWT | Aggregate stats |
| POST | /beneficiaries | Admin/Op | Create |
| PATCH | /beneficiaries/:id | Admin/Op | Update |
| DELETE | /beneficiaries/:id | Admin | Delete |
| POST | /fraud/check/:id | Admin/Op | Run fraud assessment |
| POST | /fraud/verify/aadhaar/:id | Admin/Op | Aadhaar check |
| POST | /fraud/verify/death/:id | Admin/Op | Death check |
| POST | /fraud/verify/life-cert/:id | Admin/Op | Life cert check |
| GET | /fraud/cases | JWT | List fraud cases |
| PATCH | /fraud/cases/:id | Admin/Op | Update case |
| GET | /analytics/dashboard | JWT | KPI summary |
| GET | /analytics/fraud-trend | JWT | Monthly trend |
| GET | /analytics/audit-logs | Admin | Audit log |
| GET | /notifications | JWT | User notifications |
| POST | /notifications/read | JWT | Mark read |
| POST | /notifications/read-all | JWT | Mark all read |
