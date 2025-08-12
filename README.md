# Voting System

A secure, user-friendly online voting platform built with Django. This project enables voters to register, verify their identity, and cast votes for candidates in various positions. It features an admin panel for managing elections, candidates, and positions, and provides real-time vote summaries and analytics.

## Features

- **User Registration & Authentication:** Secure sign-up, login, and logout flows.
- **Email & OTP Verification:** Ensures only verified users can vote.
- **Profile Management:** Users can update their profile and upload a profile picture.
- **Voting Process:** Cast votes for candidates in different positions, with vote preview and confirmation.
- **Admin Dashboard:** Manage positions, candidates, voters, and view vote summaries.
- **Responsive UI:** Modern, mobile-friendly design using Tailwind CSS and Bootstrap.
- **Security:** Uses RSA encryption for sensitive operations (keys in `core/keys/`).

## Project Structure

```
voting_system/
├── core/
│   ├── admin.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── tests.py
│   ├── utils.py
│   ├── views.py
│   ├── keys/
│   │   ├── generate_rsa_keys.py
│   │   ├── private_key.pem
│   │   └── public_key.pem
│   ├── migrations/
│   ├── static/
│   ├── templates/
│   └── ...
├── media/
├── voting_system/
│   ├── settings.py
│   ├── urls.py
│   └── ...
├── db.sqlite3
├── manage.py
└── ...
```

## Getting Started

### Prerequisites

- Python 3.8+
- pip (Python package manager)
- [virtualenv](https://virtualenv.pypa.io/en/latest/) (recommended)

### Installation

1. **Clone the repository:**
   ```sh
   git clone <repository-url>
   cd voting_system
   ```

2. **Create and activate a virtual environment:**
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

4. **Apply migrations:**
   ```sh
   python manage.py migrate
   ```

5. **Create a superuser (admin):**
   ```sh
   python manage.py createsuperuser
   ```

6. **Run the development server:**
   ```sh
   python manage.py runserver
   ```

7. **Access the application:**
   - User site: [http://localhost:8000/](http://localhost:8000/)
   - Admin panel: [http://localhost:8000/admin/](http://localhost:8000/admin/)

## Usage

- **Register** as a voter and verify your email.
- **Login** and update your profile if needed.
- **Vote** for your preferred candidates.
- **Admins** can manage positions, candidates, and view results from the admin dashboard.

## File Locations

- **Templates:** `core/templates/`
- **Static files (CSS, JS, images):** `core/static/`
- **Media uploads (profile/candidate images):** `media/`
- **RSA Keys:** `core/keys/`

## Security Notes

- Keep your `private_key.pem` secure and never expose it publicly.
- For production, configure proper email backend and HTTPS.

## License

This project is for educational purposes. For production use, please review and adapt security, privacy, and compliance requirements.

---

**Developed by:** Aaditya Khatri 
**Contact:** akaaditya77@gmail.com
