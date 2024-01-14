import logging
import time
from typing import Dict, List, Optional, Tuple

from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest

from .data import whitelists
from .modules import converter, evaluator, reporter
from .modules.sanitization import sanitizer
from .modules.validation import validator

logging.basicConfig(level=logging.DEBUG)


class FileUploadHandler:
    """
    Handles file upload validation and sanitization processes.
    """

    def __init__(self) -> None:
        logging.debug("[FileUploadHandler] - Initializing FileUploadHandler.")
        self.request: Optional[HttpRequest] = None
        self.upload_config: Optional[Dict] = None

    def set_request(
        self, request: HttpRequest, upload_config: Optional[Dict] = None
    ) -> None:
        """
        Sets the request and upload configuration for the handler.
        """
        if upload_config:
            if not upload_config["whitelist"]:
                whitelist_name = upload_config.get("whitelist_name", "RESTRICTIVE")
                upload_config["whitelist"] = self.get_valid_whitelist(whitelist_name)
            else:
                upload_config["whitelist"] = [
                    x.lower() for x in upload_config["whitelist"]
                ]

            logging.debug("[FileUploadHandler] - Extracting upload config.")
            logging.debug("[FileUploadHandler] - Upload config:")
            logging.debug(upload_config)

        self.request = request
        self.upload_config = upload_config or {}

    def monitor_request(self) -> Tuple[HttpRequest, List]:
        """
        Monitors and processes the request, performing file validation and sanitization.
        """
        assert self.request is not None, "Request is not set in FileUploadHandler"
        self.request.block_request = False
        self.request.middleware_timers = [time.time()]
        self.request.upload_config = self.upload_config

        files = self.convert_to_file_objects()
        files, self.request.block_request = self.validate_files(files)
        files, self.request.block_request = self.evaluate_files(files)

        assert (
            self.request.upload_config is not None
        ), "Request is not set in FileUploadHandler"

        if (
            self.request.upload_config.get("sanitization")
            and not self.request.block_request
        ):
            files = self.sanitize_files(files)

        self.create_upload_log(files)
        self.print_elapsed_time("COMPLETE")

        return self.request, files

    def monitor_response(self, response: HttpResponse) -> HttpResponse:
        """
        Monitors and processes the response, checking for suspicious content.
        """
        logging.debug("[FileUploadHandler] - Monitoring response.")
        if self.contains_suspicious_content(response):
            logging.warning(
                "[FileUploadHandler] - Response contains suspicious content."
            )
            return HttpResponseBadRequest("Response could not be delivered.")

        logging.debug("[FileUploadHandler] - Response is clean.")
        return response

    def contains_suspicious_content(self, response: HttpResponse) -> bool:
        """
        Checks if the response contains suspicious content.
        """
        monitoring_keywords = [
            b'<td class="e">Configuration File (php.ini) Path </td>',
            b'<td class="e">PHP Extension Build </td>',
            b'<h2>Traceback <span class="commands"><a href="#" onclick="return switchPastebinFriendly(this);">',
            # b'<h2>Upload Any File</h2>',
        ]

        if "_container" in response.__dict__:
            for _, elem in enumerate(response._container):
                for keyword in monitoring_keywords:
                    if keyword in elem:
                        # response._container[i] = elem.replace(keyword, b"RESTRICTED")
                        return True

        return False

    def convert_to_file_objects(self) -> List:
        """
        Converts request files to file objects.
        """
        assert self.request is not None, "Request is not set in FileUploadHandler"
        conversion = converter.request_to_base_file_objects(self.request.FILES)
        self.print_elapsed_time("Converter (request to file objects)")
        return conversion

    def convert_to_request(self, files: List) -> HttpRequest:
        """
        Converts file objects to request files.
        """
        assert self.request is not None, "Request is not set in FileUploadHandler"
        conversion = converter.file_objects_to_request(self.request, files)
        self.print_elapsed_time("Converter (file objects to request)")
        return conversion

    def validate_files(self, files: List) -> Tuple[List, bool]:
        """
        Validates the uploaded files.
        """
        assert self.request is not None, "Request is not set in FileUploadHandler"
        files, block_upload = validator.validate(files, self.request.upload_config)
        self.print_elapsed_time("Validator")

        return files, block_upload

    def evaluate_files(self, files: List) -> Tuple[List, bool]:
        """
        Evaluates the uploaded files for any additional checks.
        """
        files, block_upload = evaluator.evaluate(files, self.request)
        self.print_elapsed_time("Evaluator")

        return files, block_upload

    def sanitize_files(self, files: List) -> List:
        """
        Sanitizes the uploaded files.
        """
        assert self.request is not None, "Request is not set in FileUploadHandler"
        files = sanitizer.sanitize(files, self.request.upload_config)
        self.print_elapsed_time("Sanitizer")

        return files

    def create_upload_log(self, files: List) -> None:
        """
        Creates a log for the file upload process.
        """
        assert self.request is not None, "Request is not set in FileUploadHandler"
        uploadlogs_mode = self.request.upload_config["uploadlogs_mode"]
        if not self.request.block_request and uploadlogs_mode in ["success", "always"]:
            reporter.build_report(files)
        elif self.request.block_request and uploadlogs_mode in ["blocked", "always"]:
            reporter.build_report(files)

    # def _create_upload_log(self, files, request):

    #     uploadlogs_mode = request.upload_config["uploadlogs_mode"]

    #     if not request.block_request:
    #         print("not request.block_request")
    #         if uploadlogs_mode == "success" or uploadlogs_mode == "always":
    #             print("uploadlogs_mode == success or uploadlogs_mode == always")
    #             reporter.build_report(files)
    #     else:
    #         print("request.block_request")
    #         if uploadlogs_mode == "blocked" or uploadlogs_mode == "always":
    #             print("uploadlogs_mode == blocked or uploadlogs_mode == always")
    #             reporter.build_report(files)

    def print_elapsed_time(self, processing_step: str) -> None:
        """
        Prints the elapsed time for a processing step.
        """
        assert self.request is not None, "Request is not set in FileUploadHandler"
        curr_time = time.time()
        execution_last_step = (curr_time - self.request.middleware_timers[-1]) * 1000
        execution_until_now = (curr_time - self.request.middleware_timers[0]) * 1000

        if processing_step == "COMPLETE":
            logging.info(
                "[Middleware] - TOTAL execution time: %s sec"
                % (round(execution_until_now / 1000, 3))
            )
        else:
            logging.info(
                f"[Middleware] - {processing_step} took {round(execution_last_step, 3)} ms - Total: {round(execution_until_now / 1000, 3)} sec"
            )
        self.request.middleware_timers.append(curr_time)

    def get_valid_whitelist(self, whitelist_name: str) -> List[str]:
        """
        Retrieves the valid whitelist based on the provided whitelist name.
        """
        whitelists_mapping = {
            "AUDIO_ALL": whitelists.WHITELIST_MIME_TYPES__AUDIO_ALL,
            "APPLICATION_ALL": whitelists.WHITELIST_MIME_TYPES__APPLICATION_ALL,
            "IMAGE_ALL": whitelists.WHITELIST_MIME_TYPES__IMAGE_ALL,
            "TEXT_ALL": whitelists.WHITELIST_MIME_TYPES__TEXT_ALL,
            "VIDEO_ALL": whitelists.WHITELIST_MIME_TYPES__VIDEO_ALL,
            "AUDIO_RESTRICTIVE": whitelists.WHITELIST_MIME_TYPES__AUDIO_RESTRICTIVE,
            "APPLICATION_RESTRICTIVE": whitelists.WHITELIST_MIME_TYPES__APPLICATION_RESTRICTIVE,
            "IMAGE_RESTRICTIVE": whitelists.WHITELIST_MIME_TYPES__IMAGE_RESTRICTIVE,
            "TEXT_RESTRICTIVE": whitelists.WHITELIST_MIME_TYPES__TEXT_RESTRICTIVE,
            "VIDEO_RESTRICTIVE": whitelists.WHITELIST_MIME_TYPES__VIDEO_RESTRICTIVE,
            "ALL": whitelists.WHITELIST_MIME_TYPES__ALL,
            "RESTRICTIVE": whitelists.WHITELIST_MIME_TYPES__RESTRICTIVE,
        }
        return whitelists_mapping.get(
            whitelist_name, whitelists.WHITELIST_MIME_TYPES__RESTRICTIVE
        )
