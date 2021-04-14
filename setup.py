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
    description="Test",
    long_description=README,
    # The project's main homepage.
    url="https://github.com/IV1T3",
    # Author details
    author="Alexander Groddeck",
    author_email="agroddeck@web.de",
    classifiers=[
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
    keywords=[
        "django",
        "file upload",
        "file upload validation",
        "restricted file upload",
    ],
    packages=["django_fileuploadvalidation"],
    platforms=["OS Independent"],
    include_package_data=True,
)