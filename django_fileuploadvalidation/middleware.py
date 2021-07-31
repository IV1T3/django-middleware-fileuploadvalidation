from django.http import HttpResponseForbidden

import logging
import pprint
import sys
import time

from .config import UPLOADLOGS_MODE
from .modules.converter import basic_conversion, image_conversion
from .modules.detector import basic_detection, image_detection
from .modules.reportbuilder import basic_reportbuilding
from .modules.sanitizer import basic_sanitization, image_sanitization
from .modules.validator import basic_validation

logging.basicConfig(level=logging.DEBUG)
pp = pprint.PrettyPrinter(indent=4)

sys.dont_write_bytecode = True


class FileUploadValidationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # Start the middleware timer
        request.start_time = time.time()

        # If files have been found, activate the middleware
        if len(request.FILES) > 0:
            # init_post_request = request.POST
            init_files_request = request.FILES

            # Convert uploaded files into BaseFile class instances
            converted_base_file_objects = basic_conversion.request_to_base_file_objects(
                init_files_request
            )

            # Detect basic file information
            basic_detection_data = basic_detection.run_detection(
                converted_base_file_objects
            )

            # Validate basic file information according to upload restrictions
            (
                basic_validation_successful,
                basic_detection_data__VALIDATED,
            ) = basic_validation.run_validation(basic_detection_data)

            logging.debug(
                f"[Middleware] - basic_detection_data__VALIDATED: {pprint.pformat(basic_detection_data__VALIDATED)}"
            )
            logging.debug(f"[Middleware] - {basic_validation_successful=}")

            # If basic files information are valid
            if basic_validation_successful:

                # Convert into specific file objects.
                # TODO: Add if statement to check if base_obj is an image. Add for all file types.
                specific_file_objects = (
                    image_conversion.base_file_objects_to_image_file_objects(
                        converted_base_file_objects
                    )
                )

                # Perform file type specific detection mechanisms
                specific_detection_data = image_detection.run_image_detection(
                    specific_file_objects, basic_detection_data__VALIDATED
                )

                # TODO: Validate file type specific information according to upload restrictions
                specific_validation_successful = True

                # If specific files information are valid
                if specific_validation_successful:

                    # Basic sanitization of files
                    (
                        sanitized_data,
                        sanitized_file_objects,
                    ) = basic_sanitization.run_sanitization(
                        converted_base_file_objects,
                        specific_detection_data,
                    )

                    # Specific sanitization of files
                    # TODO: Add file type selector to distinguish between different file types

                    (
                        sanitized_data,
                        sanitized_file_objects,
                    ) = image_sanitization.run_sanitization(
                        converted_base_file_objects, specific_detection_data
                    )

                    logging.debug(
                        f"[Middleware] - sanitized_data: {pprint.pformat(sanitized_data)}"
                    )
                    logging.debug(
                        f"[Middleware] - sanitized_file_objects: {pprint.pformat(sanitized_file_objects)}"
                    )

                # Build Report

                # If request is still valid, continue with the request.

            if UPLOADLOGS_MODE == "success" or UPLOADLOGS_MODE == "always":
                basic_reportbuilding.run_reportbuilder(
                    sanitized_file_objects,
                    specific_detection_data,
                    sanitized_data,
                )

            execution_time = time.time() - request.start_time
            logging.info(f"DMF Execution time: {execution_time*1000}ms")

            if not (basic_validation_successful and specific_validation_successful):
                if UPLOADLOGS_MODE == "blocked":
                    basic_reportbuilding.run_reportbuilder(
                        converted_base_file_objects,
                        specific_detection_data,
                    )
                return HttpResponseForbidden("The file could not be uploaded.")

            sanitized_request = basic_conversion.file_objects_to_request(
                request, sanitized_file_objects
            )

        else:
            sanitized_request = request

        execution_time = time.time() - request.start_time
        logging.info(f"DMF Execution time: {execution_time*1000}ms")

        response = self.get_response(sanitized_request)

        return response
