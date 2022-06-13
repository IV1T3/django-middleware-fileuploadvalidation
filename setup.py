from setuptools import setup
import os

README = open(os.path.join(os.path.dirname(__file__), "README.md")).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

# Dynamically calculate the version based on django.VERSION.
version = __import__("django_fileuploadvalidation").get_version()

setup(
    name="django-middleware-fileuploadvalidation",
    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version=version,
    description=" A modular Django middleware to validate user file uploads, detect specially crafted media files with malicious intent and either sanitize or block them afterward.",
    long_description=README,
    long_description_content_type="text/markdown",
    # The project's main homepage.
    url="https://github.com/IV1T3/django-middleware-fileuploadvalidation",
    # Author details
    author="Alexander Groddeck, Pascal Wichmann",
    author_email="alexander.groddeck@uni-hamburg.de, pascal.wichmann@uni-hamburg.de",
    license="Apache Software License",
    classifiers=[
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
    keywords=[
        "django",
        "file upload",
        "file upload validation",
        "restricted file upload",
        "file upload sanitization",
        "file upload filtering",
        "file upload security",
    ],
    packages=["django_fileuploadvalidation"],
    platforms=["OS Independent"],
    include_package_data=True,
    install_requires=[
        "django",
        "python-dotenv",
        "python-decouple",
        "exifread",
        "pdfid",
        "python-magic",
        "pillow",
        "wand",
        "clamd",
        "quicksand",
        "oletools",
        "yara-python"
    ],
)
