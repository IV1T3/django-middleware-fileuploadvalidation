# django-middleware-fileuploadvalidation (DMF)

 A modular Django middleware to validate user file uploads, detect specially crafted media files with malicious intent and either sanitize or block them afterward. 

[![PyPI version](https://img.shields.io/pypi/v/django-middleware-fileuploadvalidation.svg?logo=pypi&logoColor=FFE873)](https://pypi.org/project/django-middleware-fileuploadvalidation/)
[![Downloads](https://img.shields.io/pypi/dw/django-middleware-fileuploadvalidation)](https://pypi.org/project/django-middleware-fileuploadvalidation/)
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

### YARA rule matching
DMF supports the detection of malicious files based on custom YARA signatures. 
Common document/PDF signature matching is already supported due to the integration of the [QuickSand](https://github.com/tylabs/quicksand) framework.
Custom YARA signatures can be placed under `/vendor/yara/`. A collection of useful YARA signatures can be found in the [awesome-yara](https://github.com/InQuest/awesome-yara) repository. The validation module will scan all files in the directory and compile the respective signatures.

### ClamAV virus scanning
DMF also utilizes the ClamAV anti-virus engine. If you would like to enable ClamAV through DMF, follow our ClamAV installation instructions: [ClamAV Install Guide](https://github.com/IV1T3/django-middleware-fileuploadvalidation/blob/main/docs/_CLAMAV_INSTALL_GUIDE.md)

## Django settings
DMF can be customized by modifying the Django project's settings.py file. Different upload restrictions can be applied on a path basis.

This example assumes that an apps urls.py includes the following paths resolving to `http://127.0.0.1:8000/upload_images/` and `http://127.0.0.1:8000/upload_pdfs/`, respectively.
```python
urlpatterns = [
    ...,
    path("upload_images/", views.upload_images),
    path("upload_pdfs/", views.upload_pdfs),
    ...,
]
```

By default, the DMF upload configuration is set as follows:
  
```python
{
  "clamav": False,
  "file_size_limit": None,
  "filename_length_limit": None,
  "keep_original_filename": False,
  "sanitization": True,
  "uploadlogs_mode": "blocked",
  "whitelist_name": "RESTRICTIVE",
  "whitelist": [],
}
```

Each field can be customized on a path basis in the settings.py file overwriting the default configuration.
These are valid example configurations:
```python
UPLOAD_CONFIGURATION = {
    # Default DMF configuration. However, only image files are allowed.
    "upload_images": {
        "whitelist_name": "IMAGES_ALL",
    },
    # Only PDF files are allowed with a file size limit of 2MB.
    # The original filename is kept.
    "upload_pdfs": {
        "file_size_limit": 200000000,
        "keep_original_filename": True,
        "whitelist_name": "CUSTOM",
        "whitelist": ["application/pdf"],
    },
}
```

### Configuration 
  - `clamav`: ClamAV is an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats. By default, ClamAV is disabled. However, if you want to enable it, you can do so by setting this to *True*.
  - `file_size_limit`: Defines the maximum allowed file size in kilobytes (kB). Files larger than this limit will be rejected. By default, the limit is set to *5000* kB.
  - `filename_length_limit`: Defines the maximum allowed character length of the file name. By default, the limit is set to 100 characters.
  - `keep_original_filename`: By default, DMF will rename the uploaded file to a random string. If you would like to keep the original filename, set this to *True*.
  - `sanitization`: DMF supports sanitization of images and PDF documents. By default, DMF will block malicious files. However, activating the sanitization will instead sanitze files and upload them consequently.
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
