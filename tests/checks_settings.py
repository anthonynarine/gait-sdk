"""A real Django settings module for the check-pack tests.

Every Django check passes with these values. Tests start from here and
override one thing at a time. Also used by the subprocess tests
(`gait-check --settings tests.checks_settings`).
"""

# A distinctive value so the leak tests can search every output for it.
SECRET_KEY = "SENTINELkey-7fQ2mZr9Lw4Xb8Nc1Vd6Hy3Tp5Js0Kq-gA7uE2oI9wR4tY6pL1zX"
SECRET_KEY_FALLBACKS = []

DEBUG = False
ALLOWED_HOSTS = ["app.example.com"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "rest_framework",
    "gait_sdk",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "tests.checks_urls"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

X_FRAME_OPTIONS = "DENY"
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True

REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_USE_TLS = True

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": [
            "django.contrib.auth.context_processors.auth",
            "django.contrib.messages.context_processors.messages",
            "django.template.context_processors.request",
        ]},
    }
]

USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
