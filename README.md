# django-middleware-fileuploadvalidation (DMF)

 A Django middleware to validate user file uploads.

[![PyPI version](https://img.shields.io/pypi/v/django-middleware-fileuploadvalidation.svg?logo=pypi&logoColor=FFE873)](https://pypi.org/project/django-middleware-fileuploadvalidation/)
[![GitHub](https://img.shields.io/github/license/IV1T3/django-middleware-fileuploadvalidation.svg)](LICENSE)

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

### ClamAV virus scanning
DMF also utilizes the ClamAV anti-virus engine. If you would like to enable ClamAV through DMF, follow our ClamAV installation instructions: [ClamAV Install Guide](_CLAMAV_INSTALL_GUIDE.md)

## Django settings
DMF can be customized by modifying the Django project's settings.py file. Different upload restrictions can be applied on a path basis.

This example assumes that an apps urls.py includes the following paths.
```python
urlpatterns = [
    ...,
    path("upload_images/", views.upload_images),
    path("upload_pdfs/", views.upload_pdfs),
    ...,
]
```

Then a default DMF configuration could look like this:
```python
UPLOAD_CONFIGURATION = {
    "upload_images": {
        "clamav": False,
        "file_size_limit": 500000000,
        "filename_length_limit": 50,
        "sanitization": True,
        "sensitivity": 0.99,
        "uploadlogs_mode": "blocked",
        "whitelist_name": "IMAGES_ALL",
    },
    "upload_pdfs": {
        "clamav": False,
        "file_size_limit": 200000000,
        "filename_length_limit": 50,
        "sanitization": True,
        "sensitivity": 0.99,
        "uploadlogs_mode": "blocked",
        "whitelist_name": "CUSTOM",
        "whitelist": ["application/pdf"],
    },
}
```

### Configuration 
  - `clamav`: ClamAV is an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats. By default, ClamAV is disabled. However, if you want to enable it, you can do so by setting this to *True*.
  - `file_size_limit`: Defines the maximum allowed file size in kilobytes (kB). Files larger than this limit will be rejected. By default, the limit is set to *5000* kB.
  - `filename_length_limit`: Defines the maximum allowed character length of the file name. By default, the limit is set to 100 characters.
  - `sanitization`: DMF performs basic file sanitization by default. This can be disabled by setting this to *False*. This will instantly block all upload attempts that seem to be malicious.
  - `sensitivity`: Threshold from which DMF denotes files as malicious. The higher the sensitivity the more strict the detection. By default, the sensitivity is set to 0.99.
  - `uploadlogs_mode`: Uploads can also be logged, to better analyze attempts afterwards. There are three different stages, which can be logged. By default, this setting is set to 'blocked'.
    - always: logs every upload attempt
    - success: logs only successful uploads
    - blocked: logs only blocked uploads
  - `whitelist_name`: DMF provides pre-defined whitelists. These can be used to prevent certain files from being uploaded. Each view can use an individual whitelist. This allows to have multiple upload forms with different whitelists. The following whitelists are available. By default, the whitelist is set to 'RESTRICTIVE'.
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
    - CUSTOM: This allows to define a custom whitelist.
  - `whitelist` (optional): If *CUSTOM* has been specified in the *whitelist_name* field, then this field requires a list of MIME types defining the custom whitelist. 
