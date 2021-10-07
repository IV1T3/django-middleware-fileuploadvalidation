"""
File Upload Validation Middleware.

This module provides a middleware that implements validation of user uploaded
files, tries to detect malicious ones, and finally either sanitizes or
blocks them afterwards.
"""

import logging
import pprint
import time

from django.http import HttpResponseForbidden

from .data import whitelists

from .modules import converter, reporter
from .modules.sanitization import sanitizer
from .modules.validation import validator

from .settings import UPLOAD_CONFIGURATION

logging.basicConfig(level=logging.INFO)
pp = pprint.PrettyPrinter(indent=4)


class FileUploadValidationMiddleware:
    def __init__(self, get_response):
        # One-time configuration and initialization.

        self.get_response = get_response

        self.block_request = None
        self.middleware_timers = None
        self.upload_config = None

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        if request.method == "POST" and len(request.FILES) > 0:

            self.upload_config = self._extract_single_upload_config(request)

            self.middleware_timers = [time.time()]
            self.block_request = False

            files = self._convert(request, convert_to="file_objects")
            files, self.block_request = self._validate_files(files)

            if not self.block_request:
                files = self._sanitize_files(files)

            self._create_upload_log(files)
            request = self._convert(request, files, convert_to="request")

            self._print_elapsed_time("COMPLETE")

            if not self.block_request:
                logging.warning(
                    "[Middleware] - File not malicious and in whitelist => Forwarding request to view."
                )
                response = self.get_response(request)
            else:
                return HttpResponseForbidden("The file could not be uploaded.")

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        return response

    def _convert(self, request, files=None, convert_to=None):
        if convert_to == "file_objects":
            conversion = converter.request_to_base_file_objects(request.FILES)
        elif convert_to == "request":
            conversion = converter.file_objects_to_request(request, files)
        else:
            return None

        self._print_elapsed_time("Converter")

        return conversion

    def _validate_files(self, files):
        files, block_upload = validator.validate(files, self.upload_config)
        self._print_elapsed_time("Validator")

        return files, block_upload

    def _sanitize_files(self, files):
        sanitization_activated = self.upload_config["sanitization"]
        if not self.block_request and sanitization_activated:
            files = sanitizer.sanitize(files)

            self._print_elapsed_time("Sanitizer")

        return files

    def _print_elapsed_time(self, processing_step):
        curr_time = time.time()
        execution_last_step = (curr_time - self.middleware_timers[-1]) * 1000
        execution_until_now = (curr_time - self.middleware_timers[0]) * 1000

        if processing_step == "COMPLETE":
            logging.info(
                "[Middleware] - TOTAL execution time: %s ms" % execution_until_now
            )
        else:
            logging.info(
                f"[Middleware] - {processing_step} took {round(execution_last_step, 3)} ms - Total: {round(execution_until_now, 3)} ms"
            )
        self.middleware_timers.append(curr_time)

    def _create_upload_log(self, files):
        uploadlogs_mode = self.upload_config["uploadlogs_mode"]

        if not self.block_request:
            if uploadlogs_mode == "success" or uploadlogs_mode == "always":
                reporter.build_report(files)
        else:
            if uploadlogs_mode == "blocked" or uploadlogs_mode == "always":
                reporter.build_report(files)

    def _extract_single_upload_config(self, request):

        upload_config = UPLOAD_CONFIGURATION

        matching_req_path = request.path[1:-1]
        if matching_req_path in upload_config:
            upload_config = upload_config[matching_req_path]
        else:
            upload_config = {
                "clamav": False,
                "file_size_limit": 500000000,
                "filename_length_limit": 100,
                "sanitization": True,
                "sensitivity": 0.99,
                "uploadlogs_mode": "blocked",
                "whitelist_name": "RESTRICTIVE",
                "whitelist_custom": [],
                "whitelist": [],
            }

        upload_config["whitelist"] = self._extract_whitelist_from_config(upload_config)

        return upload_config

    def _extract_whitelist_from_config(self, upload_config):
        if upload_config["whitelist_name"] == "CUSTOM":
            return upload_config["whitelist_custom"]
        else:
            return self._get_valid_whitelist(upload_config["whitelist_name"])

    def _get_valid_whitelist(self, whitelist_name):
        if whitelist_name == "AUDIO_ALL":
            whitelist = whitelists.WHITELIST_MIME_TYPES__AUDIO_ALL
        elif whitelist_name == "APPLICATION_ALL":
            whitelist = whitelists.WHITELIST_MIME_TYPES__APPLICATION_ALL
        elif whitelist_name == "IMAGE_ALL":
            whitelist = whitelists.WHITELIST_MIME_TYPES__IMAGE_ALL
        elif whitelist_name == "TEXT_ALL":
            whitelist = whitelists.WHITELIST_MIME_TYPES__TEXT_ALL
        elif whitelist_name == "VIDEO_ALL":
            whitelist = whitelists.WHITELIST_MIME_TYPES__VIDEO_ALL
        elif whitelist_name == "AUDIO_RESTRICTIVE":
            whitelist = whitelists.WHITELIST_MIME_TYPES__AUDIO_RESTRICTIVE
        elif whitelist_name == "APPLICATION_RESTRICTIVE":
            whitelist = whitelists.WHITELIST_MIME_TYPES__APPLICATION_RESTRICTIVE
        elif whitelist_name == "IMAGE_RESTRICTIVE":
            whitelist = whitelists.WHITELIST_MIME_TYPES__IMAGE_RESTRICTIVE
        elif whitelist_name == "TEXT_RESTRICTIVE":
            whitelist = whitelists.WHITELIST_MIME_TYPES__TEXT_RESTRICTIVE
        elif whitelist_name == "VIDEO_RESTRICTIVE":
            whitelist = whitelists.WHITELIST_MIME_TYPES__VIDEO_RESTRICTIVE
        elif whitelist_name == "ALL":
            whitelist = whitelists.WHITELIST_MIME_TYPES__ALL
        else:  # RESTRICTIVE or other
            whitelist = whitelists.WHITELIST_MIME_TYPES__RESTRICTIVE

        return whitelist
