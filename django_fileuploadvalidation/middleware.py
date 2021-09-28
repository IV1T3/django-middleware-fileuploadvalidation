from django.http import HttpResponseForbidden

import logging
import pprint
import sys
import time

from .modules.converter import conversion
from .modules.detector import basic_detection, image_detection
from .modules.reportbuilder import basic_reportbuilding

from .modules.sanitizer import sanitizer

from .modules.validator import basic_validation

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
            base_file_objects = conversion.request_to_base_file_objects(
                init_files_request
            )

            # Detect basic file information
            basic_detection_objects = basic_detection.run_detection(
                base_file_objects
            )

            # Validate basic file information according to upload restrictions
            (
                basic_validation_successful,
                basic_validation_objects,
            ) = basic_validation.run_validation(basic_detection_objects)

            logging.debug(
                f"[Middleware] - basic_validation_objects: {pprint.pformat(basic_validation_objects)}"
            )
            logging.debug(f"[Middleware] - {basic_validation_successful=}")

            # If basic files information are valid
            if basic_validation_successful:

                print(basic_validation_objects)

                # Perform file type specific detection mechanisms
                specific_validation_objects = image_detection.run_image_detection(
                    basic_validation_objects
                )

                # TODO: Validate file type specific information according to upload restrictions
                specific_validation_successful = True

                # If specific files information are valid
                if specific_validation_successful:

                    sanitized_file_objects = sanitizer.sanitize(specific_validation_objects)

                    logging.debug(
                        f"[Middleware] - sanitized_file_objects: {pprint.pformat(sanitized_file_objects)}"
                    )
                    logging.debug(
                        f"[Middleware] - sanitized_file_objects: {pprint.pformat(sanitized_file_objects)}"
                    )

                # Build Report

                # If request is still valid, continue with the request.

            if basic_validation_successful and specific_validation_successful:
                if UPLOADLOGS_MODE == "success" or UPLOADLOGS_MODE == "always":
                    basic_reportbuilding.run_reportbuilder(sanitized_file_objects)

                sanitized_request = conversion.file_objects_to_request(
                    request, sanitized_file_objects
                )
                response = self.get_response(sanitized_request)
            else:
                if UPLOADLOGS_MODE == "blocked":
                    if basic_validation_successful:
                        basic_reportbuilding.run_reportbuilder(
                            basic_validation_objects,
                        )
                    else:
                        basic_reportbuilding.run_reportbuilder(
                            basic_validation_objects,
                        )
                response = HttpResponseForbidden("The file could not be uploaded.")

        else:
            response = self.get_response(request)

        execution_time_in_ms = (time.time() - request_start_time) * 1000
        logging.info(f"DMF Execution time: {execution_time_in_ms}ms")

        return response
