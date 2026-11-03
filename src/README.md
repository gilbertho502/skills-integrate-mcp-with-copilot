# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Teacher login to sign up or unregister students
- Public access to activity schedules and participant lists

## Configure teacher accounts

Teacher passwords are stored as PBKDF2-SHA256 hashes in `teachers.json`. Add each teacher to its `teachers` array using this shape:

```json
{
  "teachers": [
    {
      "username": "teacher",
      "password_hash": "pbkdf2_sha256$310000$SALT_HEX$HASH_HEX"
    }
  ]
}
```

Generate a password hash with Python, replacing `YOUR_PASSWORD` with the assigned password:

```python
import hashlib
import secrets

password = "YOUR_PASSWORD"
salt = secrets.token_bytes(16)
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
print(f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}")
```

Do not commit real teacher credentials or password hashes to a public repository. Set `SESSION_SECRET` to a long, random value in the server environment so signed sessions remain valid across restarts and workers. Set `COOKIE_SECURE=true` when serving the app over HTTPS; the default supports local HTTP development. Teacher sessions expire after eight hours.

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   python app.py
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/auth/login`                                                      | Log in with a teacher username and password                         |
| GET    | `/auth/status`                                                     | Check whether the current session is authenticated                  |
| POST   | `/auth/logout`                                                     | End the current teacher session                                      |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | (Teacher only) Sign up a student                                     |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | (Teacher only) Unregister a student                               |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
