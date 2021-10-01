# django-middleware-fileuploadvalidation (DMF)

[comment]: <> ([![pypi-version]][pypi]) 

## Installing

This package can be installed via pip:

```bash
$ pip install django-middleware-fileuploadvalidation
```

Then add `django_fileuploadvalidation.middleware.FileUploadValidationMiddleware` to the end of your `MIDDLEWARE` in settings.py.

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    ...,
    'django_fileuploadvalidation.middleware.FileUploadValidationMiddleware',
]
```

### IMPORTANT: the latest version of pdfid is currently not compatible with this package.
DMF requires the changes of the pdfid library as of pull request #3: https://github.com/mlodic/pdfid/pull/3.
After having installed pdfid, please substitute your installed pdfid.py with https://github.com/IV1T3/pdfid/blob/main/pdfid/pdfid.py to maintain compatibility.

We hope, PR #3 will be merged and published as soon as possible such that it is no longer necessary to substitute the pdfid library.

### Installing ClamAV on macOS

This package also utilizes the ClamAV anti-virus engine. For this, it is required to have a running instance of the ClamAV daemon.

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

Restart the clamAV daemon.

### Installing ClamAV on Ubuntu

```bash
$ sudo apt-get install clamav-daemon clamav-freshclam clamav-unofficial-sigs
$ sudo freshclam
$ sudo service clamav-daemon start
```

To further configure your ClamAV daemon, modify either `/etc/clamav/clamd.conf` or `/etc/clamav/freshclam.conf`.


[pypi]: https://pypi.org/project/django-cprofile-middleware/
[pypi-version]: https://img.shields.io/pypi/v/django-cprofile-middleware.svg

## Settings
DMF can also be customized by modifying the Django project's settings file.

### ClamAV Usage
ClamAV is an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats. By default, ClamAV is enabled. However, if you want to disable it, you can do so by setting the `CLAMAV_USAGE` setting to `False`.
```python
CLAMAV_USAGE = False
```

### Detection sensitivity
Threshold from which DMF denotes files as malicious.
The higher the sensitivity the more strict the detection.
By default, the sensitivity is set to 0.99.
```python
DETECTOR_SENSITIVITY = 0.99
```

### File size limit
Defines the maximum allowed file size in kilobytes (kB). Files larger than this limit will be rejected. By default, the limit is set to `5000` kB.
```python
FILE_SIZE_LIMIT = 5000
```

### File name length limit
Defines the maximum allowed character length of the file name.
By default, the limit is set to 100 characters.
```python
FILENAME_LENGTH_LIMIT = 100
```

### Logging upload requests
Uploads can also be logged, to better analyze attempts afterwards.
There are three different stages, which can be logged:
- always: logs every upload attempt
- success: logs only successful uploads
- blocked: logs only blocked uploads
  
By default, this setting is set to 'blocked'.
```python
UPLOADLOGS_MODE = 'blocked'
```

### Whitelists
DMF provides pre-defined whitelists. These can be used to prevent certain files from being uploaded. The following whitelists are available:


- ALL: All files
  - AUDIO_ALL: All audio files
  - APPLICATION_ALL: All application files
  - IMAGE_ALL: All image files
  - TEXT_ALL: All text files
  - VIDEO_ALL: All video files
- RESTRICTIVE: All restricted whitelists combined
  - AUDIO_RESTRICTIVE: audio/mpeg
  - APPLICATION_RESTRICTIVE: application/pdf
  - IMAGE_RESTRICTIVE: image/gif, image/jpeg, image/png, image/tiff
  - TEXT_RESTRICTIVE: text/plain
  - VIDEO_RESTRICTIVE: video/mp4, video/mpeg
- CUSTOM: Define your own whitelist

By default, the whitelist is set to 'RESTRICTIVE'.

```python
UPLOAD_MIME_TYPE_WHITELIST = 'RESTRICTIVE'
```

You can also define whitelists by yourself by creating a custom whitelist in your settings file. For this, set the `UPLOAD_MIME_TYPE_WHITELIST` setting to `CUSTOM` and define a list of mime types called `CUSTOM_WHITELIST`. See the following example:
```python
UPLOAD_MIME_TYPE_WHITELIST = 'CUSTOM'
CUSTOM_WHITELIST = ['image/png', 'video/mp4']
```

### Sanitization mode
DMF performs basic file sanitization by default. This can be disabled by setting the `SANITIZATION_ACTIVATED` setting to `False`. This will instantly block all upload attempts that seem to be malicious.
```python
SANITIZATION_ACTIVATED = 'FALSE'
```