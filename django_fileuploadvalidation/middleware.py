from django.http import HttpResponseForbidden

import logging
import pprint
import sys
import time

from .modules import converter
from .modules.detector import detector
from .modules.reportbuilder import basic_reportbuilding
from .modules.sanitizer import sanitizer

from .settings import UPLOADLOGS_MODE, SANITIZATION_ACTIVATED

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
            files, block_upload = detector.detect(files)

            # validation_success = False

            if not block_upload:

                # If basic files information are valid
                if SANITIZATION_ACTIVATED:

                    # Sanitize uploaded files
                    files = sanitizer.sanitize(files)

                    logging.debug(
                        f"[Middleware] - sanitized files: {pprint.pformat(files)}"
                    )

            # Build Report

            # If request is still valid, continue with the request.

            if not block_upload:
                if UPLOADLOGS_MODE == "success" or UPLOADLOGS_MODE == "always":
                    basic_reportbuilding.build_report(files)

                sanitized_request = converter.file_objects_to_request(request, files)
                response = self.get_response(sanitized_request)
            else:
                if UPLOADLOGS_MODE == "blocked" or UPLOADLOGS_MODE == "always":
                    basic_reportbuilding.build_report(files)
                response = HttpResponseForbidden("The file could not be uploaded.")

        else:
            response = self.get_response(request)

        execution_time_in_ms = (time.time() - request_start_time) * 1000
        logging.info(f"DMF Execution time: {execution_time_in_ms}ms")

        return response
