# django-middleware-fileuploadvalidation

[![pypi-version]][pypi]

## Installing

This package can be installed via pip:

```bash
$ pip install django-middleware-fileuploadvalidation
```

Then add `django_fileuploadvalidation.middleware.FileUploadValidationMiddleware` to the end of your `MIDDLEWARE` in settings.py.

```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    ...,
    "django_fileuploadvalidation.middleware.FileUploadValidationMiddleware",
]
```

[pypi]: https://pypi.org/project/django-cprofile-middleware/
[pypi-version]: https://img.shields.io/pypi/v/django-cprofile-middleware.svg
