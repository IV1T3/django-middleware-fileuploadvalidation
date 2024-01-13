# django-middleware-fileuploadvalidation (DMF)

This Django middleware provides robust validation and sanitization for file uploads. It is designed to ensure the security and integrity of files uploaded through Django applications by performing various checks, validations, and sanitization processes.

[![PyPI version](https://img.shields.io/pypi/v/django-middleware-fileuploadvalidation.svg?logo=pypi&logoColor=FFE873)](https://pypi.org/project/django-middleware-fileuploadvalidation/)
[![Downloads](https://img.shields.io/pypi/dw/django-middleware-fileuploadvalidation)](https://pypi.org/project/django-middleware-fileuploadvalidation/)
[![GitHub](https://img.shields.io/github/license/IV1T3/django-middleware-fileuploadvalidation.svg)](LICENSE)

> :warning: **Breaking Changes in Version 1.0.0**: We've introduced a significant update to the upload configuration method. This change transitions from a per-path basis in the settings.py to a more flexible per-view basis using decorators. You can now configure uploads directly at the view level using decorators, offering more granular control. Please update your implementations accordingly to accommodate these changes. Examples of the new configuration method can be found in the [Configuration](#configuration) section below.

## Features
- **File Validation**: Checks file types, sizes, and signatures to verify the authenticity and integrity of uploaded files.
- **File Sanitization**: Cleans and modifies files to remove potentially harmful content, ensuring safe file handling.
- **Configurable Settings**: Flexible configuration options to customize validation and sanitization rules based on specific needs.
- **Comprehensive Logging**: Detailed logging for audit trails and debugging.
- **Support for Multiple File Types**: Custom handlers for different file types (images, documents, etc.) with tailored validation and sanitization logic.

## Installation


This package can be installed via pip:

```bash
pip install django-middleware-fileuploadvalidation
```

Then add `django_middleware_fileuploadvalidation.middleware.FileUploadValidationMiddleware` to the end of your `MIDDLEWARE` in settings.py.

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    ...,
    'django_middleware_fileuploadvalidation.middleware.FileUploadValidationMiddleware',
]

```

### YARA rule matching
DMF supports the detection of malicious files based on custom YARA signatures. 
Common document/PDF signature matching is already supported due to the integration of the [QuickSand](https://github.com/tylabs/quicksand) framework.
Custom YARA signatures can be placed under `/vendor/yara/`. A collection of useful YARA signatures can be found in the [awesome-yara](https://github.com/InQuest/awesome-yara) repository. The validation module will scan all files in the directory and compile the respective signatures.

### ClamAV virus scanning
DMF also utilizes the ClamAV anti-virus engine. If you would like to enable ClamAV through DMF, follow our ClamAV installation instructions: [ClamAV Install Guide](https://github.com/IV1T3/django-middleware-fileuploadvalidation/blob/main/docs/_CLAMAV_INSTALL_GUIDE.md)

## Configuration
By default, the upload configuration is set to the following:
```python
{
    "clamav": False,
    "file_size_limit": None,
    "filename_length_limit": None,
    "keep_original_filename": False,
    "sanitization": True,
    "uploadlogs_mode": "blocked",
    "whitelist_name": "RESTRICTED",
    "whitelist": [],
}
```

The middleware can be configured by adding a decorator to the respective view function that should be protected. Each field can be individually configured by passing the respective parameter to the decorator.

```python
from django_middleware_fileuploadvalidation.decorators import file_upload_config

@file_upload_config()
def upload_default_view(request):
    # View logic for uploading files
    ...

@file_upload_config(file_size_limit=2000000, keep_original_filename=True, whitelist=["application/pdf"])
def upload_pdf_view(request):
    # View logic for uploading PDF files
    ...

@file_upload_config(whitelist_name="IMAGES_ALL")
def upload_image_view(request):
    # View logic for uploading images
    ...
```

### Options 
  - `clamav`: ClamAV is an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats. By default, ClamAV is disabled. However, if you want to enable it, you can do so by setting this to *True*.
  - `file_size_limit`: Defines the maximum allowed file size in kilobytes (kB). Files larger than this limit will be rejected. By default, there is no file size limit set.
  - `filename_length_limit`: Defines the maximum allowed character length of the file name. By default, there is no file length limit set.
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
  - `whitelist`: If you want to use a custom whitelist, you can define it here. The whitelist must be a list of strings. Each string must be a valid MIME type. For example: `["application/pdf", "image/png"]`. This setting will override the `whitelist_name` setting.