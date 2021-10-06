"""
File Upload Validation Middleware.

This module provides a middleware that implements validation of user uploaded
files, tries to detect malicious ones, and finally either sanitizes or
blocks them afterwards.
"""

import logging
import pprint
import time

from django.conf import settings
from django.http import HttpResponseForbidden

from .data import whitelists

from .modules import converter, reporter
from .modules.validation import validator
from .modules.sanitization import sanitizer

logging.basicConfig(level=logging.INFO)
pp = pprint.PrettyPrinter(indent=4)


class FileUploadValidationMiddleware:
    def __init__(self, get_response):
        # One-time configuration and initialization.

        self.get_response = get_response
        self.options = getattr(
            settings,
            "VIEW_UPLOAD_CONFIGURATION",
            {"default": {"whitelist": "RESTRICTIVE"}},
        )

        self.view_whitelist_mapping = self._view_upload_confs_to_whitelist_mimes(
            self.options
        )

        self.middleware_timers = None
        self.block_request = None

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        if request.method == "POST" and len(request.FILES) > 0:

            self.middleware_timers = [time.time()]
            self.block_request = False

            files = self._convert(request, convert_to="file_objects")
            files, self.block_request = self._validate_files(files)
            files = self._sanitize_files(files)
            self._create_upload_log(files)
            request = self._convert(request, files, convert_to="request")

            self._print_elapsed_time("COMPLETE")

            request.guessed_mimes = []
            for file_name, file in files.items():
                request.guessed_mimes.append(file.detection_results.guessed_mime)

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        # Code to be executed after the first step of __call__ and
        # before get_response(). It finally verifies that the
        # uploaded files are on the specified whitelist.

        if request.method == "POST" and len(request.FILES) > 0:
            url_name = request.resolver_match.url_name
            files_whitelisted = self._verify_mime_in_whitelist(
                url_name, request.guessed_mimes
            )

            if not self.block_request and files_whitelisted:
                logging.warning(
                    "[Middleware] - File not malicious and in whitelist => Forwarding request to view."
                )
                return None
            else:
                if self.block_request:
                    logging.warning(
                        "[Middleware] - File might be malicious => Blocking request."
                    )
                if not files_whitelisted:
                    logging.warning(
                        "[Middleware] - Files not whitelisted => Blocking request."
                    )
                return HttpResponseForbidden("The file could not be uploaded.")

        return None

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
        files, block_upload = validator.validate(files, self.options)
        self._print_elapsed_time("Validator")

        return files, block_upload

    def _sanitize_files(self, files):
        sanitization_activated = getattr(settings, "SANITIZATION_ACTIVATED", True)
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
        uploadlogs_mode = getattr(settings, "UPLOADLOGS_MODE", "blocked")

        if not self.block_request:
            if uploadlogs_mode == "success" or uploadlogs_mode == "always":
                reporter.build_report(files)
        else:
            if uploadlogs_mode == "blocked" or uploadlogs_mode == "always":
                reporter.build_report(files)

    def _verify_mime_in_whitelist(self, url_name, mime_types):
        in_whitelist = [
            1 if mime in self.view_whitelist_mapping[url_name] else 0
            for mime in mime_types
        ]
        return all(in_whitelist)

    def _view_upload_confs_to_whitelist_mimes(self, view_upload_confs):
        whitelist_mimes = {}
        for view_name, upload_conf in view_upload_confs.items():
            whitelist_mimes[view_name] = self._get_valid_whitelist(
                upload_conf["whitelist"]
            )

        return whitelist_mimes

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
        # elif whitelist_name == "CUSTOM":
        #     whitelist = getattr(settings, "CUSTOM_WHITELIST", None)
        else:  # RESTRICTIVE or other
            whitelist = whitelists.WHITELIST_MIME_TYPES__RESTRICTIVE

        return whitelist
