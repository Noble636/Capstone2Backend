# Apartment Maintenance — Tenant Complaint & Security Management System

Apartment Maintenance is a web-based Tenant Complaint and Security Management System that centralizes maintenance requests, visitor logging, and administrative workflows for apartment complexes.

The system is designed to replace manual and fragmented processes (paper logs, phone calls, and ad-hoc messages) with a single, auditable platform that improves response time, transparency, and accountability. Tenants can submit detailed maintenance requests and track progress, while administrators and maintenance staff receive timely notifications and tools to assign and resolve work orders.

Intended users include tenants, property managers, maintenance crews, and security personnel. Role-based access ensures each user sees the appropriate interface and data. The project is implemented as a modular stack: a React frontend, a Node.js/Express API, and a MySQL database (Aiven in production). Email-based OTP verification via the Gmail API is used for sensitive authentication flows.

## Authors
- Danyael Kaye C. Apil
- John Nikko B. Arangorin
- John Peter C. Gonzales
- Shane B. Salonga
- Jacques Lynn B. Toledo

## Deployments
- Frontend (Vercel): replace with project URL
- Backend (Render): replace with project URL

## Features
- Submit and track maintenance complaints
- Admin dashboard: assign, update, resolve tasks
- Visitor entry/exit logging for security
- Role-based access control (Tenant, Admin/Manager, Security)
- Email OTP verification (Gmail API)

Each feature in brief:
- Complaint submission: Tenants can create maintenance requests with category, priority, description, and optional attachments. Submissions include timestamps and an auto-generated complaint ID.
- Complaint tracking: Tenants and admins can view complaint status (Submitted, In Progress, Resolved, Closed), comments, and resolution timestamps. History is maintained per tenant.
- Admin dashboard: Property managers can view all complaints, filter by priority/status, assign work to maintenance staff, and record resolution notes.
- Visitor management: Security personnel can register visitor entries and exits, record visitor details and purpose, and search visitor logs for a given date range.
- Role-based access: The system enforces roles so each user sees only the interfaces and actions permitted to their role.
- Email OTP verification: On sensitive flows (e.g., registration or password reset), the system issues a one-time password via Gmail API to verify the user's email.

## Tech Stack
- Frontend: React (Create React App)
- Backend: Node.js + Express
- Database: MySQL (Aiven managed MySQL in production)
- Tools: MySQL Workbench for DB management; Gmail API for email/OTP

## Repository layout
- `tenantportal/` — frontend React app
- `tenantportalbackend/` — backend Node/Express API (includes `server.js`, mailer utilities, and `SQL Codes/`)
- `Capstone 2.txt` — project documentation and write-up

## How it works (high level)
- User accounts: Tenants, Admins, and Security staff register and authenticate. JWT-based sessions or tokens are used for API requests.
- Complaint flow: Tenant creates complaint -> Admin receives and assigns -> Maintenance updates status -> Admin/tenant confirm resolution.
- Visitor flow: Security logs visitor entry -> optional admin/tenant notification -> security logs exit when visitor leaves.

## User roles
- Tenant: Submit and view own complaints; view relevant notices and confirmations.
- Admin / Manager: Full access to complaint lists, assignment, user management, and reports.
- Security: Access to visitor logs, search, and daily reports.

## Quick start (development)

1. Frontend

```powershell
cd tenantportal
npm install
npm start
```

2. Backend

```powershell
cd tenantportalbackend
npm install
node server.js
```

3. Database
- Use Aiven (production) or a local MySQL instance. Use MySQL Workbench to connect and run the SQL scripts in `tenantportalbackend/SQL Codes` to create schema and seed data.

## Environment variables (backend)
Create a `.env` in `tenantportalbackend/` with at minimum:

```
PORT=3001
DB_HOST=<host>
DB_USER=<user>
DB_PASSWORD=<password>
DB_NAME=<database>
JWT_SECRET=<secret>
GMAIL_CLIENT_ID=<id>
GMAIL_CLIENT_SECRET=<secret>
GMAIL_REFRESH_TOKEN=<refresh_token>
EMAIL_FROM=<email>
```

Do not commit secrets to version control.

## Build (frontend)

```powershell
cd tenantportal
npm run build
```

## Deployment notes
- Set backend environment variables on Render and configure the managed MySQL instance (Aiven) connection.
- Configure frontend build to point to the deployed backend API base URL.

## Testing
- Frontend: `npm test` in `tenantportal/` if tests exist.
- Backend: add and run tests as configured (Jest/Mocha) if present.

## Contact
For questions or support, contact any of the project team members:

- Danyael Kaye C. Apil — `klmnopq1221@gmail.com`
- Jacques Lynn Toledo — `jaiddes6@gmail.com`
- Shane B. Salonga — `shanesalonga736@gmail.com`
- John Peter C. Gonzales — `pedromeh21@gmail.com`
- John Nikko B. Arangorin — `nikkoarangorin004@gmail.com`

For general inquiries, use any of the emails above; response times may vary.

