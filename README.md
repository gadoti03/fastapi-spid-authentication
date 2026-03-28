# FastAPI SPID Wrapper

FastAPI backend that handles the full SPID authentication flow for a Service Provider. It manages communication with Identity Providers, builds and validates SAML messages, and exposes ready-to-use endpoints for login, logout, and session management.

## Demo

In this demo, I created a frontend in React that interacts with the backend in this repository.  
It shows the workflow of **authentication** and **logout** using SPID.

![Demo of SPID authentication workflow](screencast.gif)

> The GIF above demonstrates the full login and logout flow with SPID, connecting the React frontend to the backend.

---

## Requirements

* Python 3.11+
* PostgreSQL
* Virtualenv (recommended)

Install dependencies:

```bash
pip install -r requirements.txt
```

**Note:** If you update `requirements.txt`, you can regenerate it with:

```bash
pip freeze > requirements.txt
```

---

## Database

The project uses **PostgreSQL** as the database.

Create a dedicated database:

```sql
CREATE DATABASE spid_db;
CREATE USER admin WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE spid_db TO admin;
```

Update the connection string in `alembic.ini` before running migrations:

```ini
sqlalchemy.url = postgresql+psycopg2://admin:password@localhost:5432/spid_db
```

Run migrations:

```bash
alembic upgrade head
```

---

## Alembic

The project uses Alembic for database migrations:

* Migration files are located in `alembic/versions`.
* Update the connection string in `alembic.ini` before applying migrations.
* Main commands:

```bash
alembic revision --autogenerate -m "migration message"
alembic upgrade head
```

---

## Certificate Rotation

Certificates can be rotated using the provided script:

```bash
python3 spid/scripts/certificate_manager.py
```

This script generates and updates SPID certificates required for SAML communication.

---

## Running the Application

Start the FastAPI server:

```bash
uvicorn main:app --reload
```

Endpoints for login, logout, and session management will be available at `/...` and `/spid/...`.

---

## License

See the [LICENSE](LICENSE) file for details.
 