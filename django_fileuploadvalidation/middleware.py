from django.http import HttpResponseForbidden
from django.contrib import messages

import logging
import pprint

from .config import UPLOADLOGS_MODE
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

            one_file_blocked = False
            for key in detection_data:
                if detection_data[key]["file"]["block"]:
                    one_file_blocked = True
                    break

            if not one_file_blocked:
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

                    if file_block:
                        # messages.error(request, "The file couldn't been uploaded.")
                        # TODO: Display error message and forward to upload page.
                        if UPLOADLOGS_MODE == "blocked":
                            reportbuilder.run_reportbuilder(
                                converted_file_objects,
                                detection_data,
                            )
                        return HttpResponseForbidden("The file couldn't been uploaded.")

                sanitized_request = converter.file_objects_to_request(
                    request, sanitized_file_objects
                )
            else:
                # messages.error(request, "The file couldn't been uploaded.")
                # TODO: Display error message and forward to upload page.
                if UPLOADLOGS_MODE == "blocked":
                    reportbuilder.run_reportbuilder(
                        converted_file_objects,
                        detection_data,
                    )
                return HttpResponseForbidden("The file couldn't been uploaded.")
            
            if UPLOADLOGS_MODE == "success" or UPLOADLOGS_MODE == "always":
                reportbuilder.run_reportbuilder(
                    sanitized_file_objects,
                    detection_data,
                    sanitized_data,
                )

        else:
            sanitized_request = request

        response = self.get_response(sanitized_request)
        

        return response