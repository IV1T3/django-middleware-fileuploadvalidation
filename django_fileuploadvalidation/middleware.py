from django.http import HttpResponseForbidden
from django.contrib import messages

import logging
import pprint

from .config import ALWAYS_ENABLED_UPLOADLOGS
from .modules import converter, detector, reportbuilder, sanitizer

logging.basicConfig(level=logging.DEBUG)
pp = pprint.PrettyPrinter(indent=4)


class FileUploadValidationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        if len(request.FILES) > 0:
            init_post_request = request.POST
            init_files_request = request.FILES

            converted_file_objects = converter.request_to_file_objects(
                init_files_request
            )
            detection_data = detector.run_detection(
                init_post_request, converted_file_objects
            )

            logging.debug(
                f"[Middleware] - detection_data: {pprint.pformat(detection_data)}"
            )

            sanitized_data, sanitized_file_objects = sanitizer.run_sanitization(
                init_post_request, converted_file_objects, detection_data
            )

            logging.debug(
                f"[Middleware] - sanitized_data: {pprint.pformat(sanitized_data)}"
            )
            logging.debug(
                f"[Middleware] - sanitized_file_objects: {pprint.pformat(sanitized_file_objects)}"
            )

            for sanitized_file_object_key in sanitized_file_objects:
                file_block = sanitized_file_objects[sanitized_file_object_key].block

                if ALWAYS_ENABLED_UPLOADLOGS or not file_block:
                    reportbuilder.run_reportbuilder(
                        sanitized_file_objects,
                        detection_data,
                        sanitized_data,
                    )

                if file_block:
                    messages.error(request, "The file couldn't been uplaoded.")
                    # TODO: Display error message and forward to upload page.
                    return HttpResponseForbidden()

            sanitized_request = converter.file_objects_to_request(
                request, sanitized_file_objects
            )
        else:
            sanitized_request = request

        response = self.get_response(sanitized_request)

        return response