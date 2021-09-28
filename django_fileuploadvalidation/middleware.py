from django.http import HttpResponseForbidden

import logging
import pprint
import sys
import time

from .modules import converter
from .modules.detector import detector
from .modules.reportbuilder import basic_reportbuilding
from .modules.sanitizer import sanitizer
from .modules.validator import validator

from .settings import UPLOADLOGS_MODE

logging.basicConfig(level=logging.DEBUG)
pp = pprint.PrettyPrinter(indent=4)

sys.dont_write_bytecode = True


class FileUploadValidationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # Start the middleware timer
        request_start_time = time.time()
        mw_return_val = request

        # If files have been found, activate the middleware
        if len(request.FILES) > 0:

            init_files_request = request.FILES

            # Convert uploaded files into File class instances
            files = converter.request_to_base_file_objects(init_files_request)

            # Detect file information
            detected_files, block_upload = detector.detect(files)

            val_success = False

            if not block_upload:

                # Validate file information according to upload restrictions
                val_files, val_success = validator.validate(detected_files)

                # If basic files information are valid
                if val_success:

                    # Sanitize uploaded files
                    sanitized_file_objects = sanitizer.sanitize(val_files)

                    logging.debug(
                        f"[Middleware] - sanitized_file_objects: {pprint.pformat(sanitized_file_objects)}"
                    )
                    logging.debug(
                        f"[Middleware] - sanitized_file_objects: {pprint.pformat(sanitized_file_objects)}"
                    )

            # Build Report

            # If request is still valid, continue with the request.

            if not block_upload and val_success:
                if UPLOADLOGS_MODE == "success" or UPLOADLOGS_MODE == "always":
                    basic_reportbuilding.build_report(sanitized_file_objects)

                sanitized_request = converter.file_objects_to_request(
                    request, sanitized_file_objects
                )
                response = self.get_response(sanitized_request)
            else:
                if UPLOADLOGS_MODE == "blocked":
                    if val_success:
                        basic_reportbuilding.build_report(
                            val_files,
                        )
                    else:
                        basic_reportbuilding.build_report(
                            detected_files,
                        )
                response = HttpResponseForbidden("The file could not be uploaded.")

        else:
            response = self.get_response(request)

        execution_time_in_ms = (time.time() - request_start_time) * 1000
        logging.info(f"DMF Execution time: {execution_time_in_ms}ms")

        return response
