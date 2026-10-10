# Sistema de Autenticación con OTP (FastAPI)

Parcial de Desarrollo de Software. API con registro, login, OTP por correo y JWT.

## Stack
Python 3.9+, FastAPI, SQLAlchemy, SQLite, PyOTP, smtplib, pytest.

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # Windows: copy .env.example .env
```

## Envío de correos (OTP)

El login envía un código OTP por correo. En `.env`:

- **Desarrollo:** `EMAIL_BACKEND=console` imprime el código en la terminal del servidor (sin SMTP).
- **Producción:** `EMAIL_BACKEND=smtp` y completar `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`.

Si `EMAIL_BACKEND` no está definido se usa `smtp`, y sin credenciales el login responde 503.

## Ejecutar

```bash
python -m uvicorn app.main:app --reload
```

- API: http://127.0.0.1:8000
- Documentación interactiva (Swagger): http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/health

## Tests

```bash
python -m pytest
```

## Estructura

```
app/
├── __init__.py
├── main.py            # aplicación principal
├── models.py          # modelos SQLAlchemy
├── schemas.py         # esquemas Pydantic
├── database.py        # configuración de la BD
├── middleware.py      # validación de tokens
├── routes/
│   ├── auth.py        # endpoints de autenticación
│   └── users.py       # endpoints de usuarios
└── services/
    ├── email_service.py
    └── otp_service.py
tests/
```

## Estado de los endpoints

| Método | Ruta | Estado |
|---|---|---|
| POST | /auth/register | implementado |
| POST | /auth/login | implementado |
| POST | /auth/verify-otp | pendiente |
| POST | /auth/refresh | pendiente |
| POST | /auth/logout | pendiente |
| POST | /auth/resend-otp | pendiente |
| GET | /users/profile | pendiente |
| PUT | /users/profile | pendiente |

## Flujo de ramas sugerido

`main` ← `feature/register`, `feature/login`, etc. Un commit por tarea.
