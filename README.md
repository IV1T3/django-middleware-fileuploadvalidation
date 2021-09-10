# django-middleware-fileuploadvalidation

[comment]: <> ([![pypi-version]][pypi]) 

## Installing

Soon, this package can be installed via pip:

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

This package also utilizes the ClamAV anti-virus engine. For this, it is required to have a running instance of the ClamAV daemon.

To install a ClamAV daemon on macOS using Homebrew:

```bash
$ brew install clamav
$ cd /usr/local/etc/clamav
$ cp freshclam.conf.sample freshclam.conf
$ cp clamd.conf.sample clamd.conf
```

Open `freshclam.conf` and either comment or remove the "Example" line:
```bash
# Comment or remove the line below.
# Example
```

In `clamd.conf`, uncomment the line "LocalSocket" and set it to the path of the socket file:
```bash
LocalSocket /var/run/clamav/clamd.ctl
LocalSocketGroup clamav
```

Afterwards, update the local ClamAV database.
```bash
$ freshclam
```

And restart the ClamAV daemon (Linux):
```bash
$ sudo service clamav-daemon restart
```

Installing ClamAV daemon under Ubuntu (not tested):
```bash
$ sudo apt-get install clamav-daemon clamav-freshclam clamav-unofficial-sigs
$ sudo freshclam
$ sudo service clamav-daemon start
```


[pypi]: https://pypi.org/project/django-cprofile-middleware/
[pypi-version]: https://img.shields.io/pypi/v/django-cprofile-middleware.svg
