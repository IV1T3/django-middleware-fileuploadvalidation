"""
File Upload Validation Middleware.

This module provides a middleware that implements validation of user uploaded
files, tries to detect malicious ones, and finally either sanitizes or
blocks them afterwards.
"""

import asyncio
import logging
import pprint

# from asgiref.sync import async_to_sync        TODO: Do research on this.
from typing import Any

from django.contrib import messages
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin

from .FileUploadHandler import FileUploadHandler

logging.basicConfig(level=logging.DEBUG)
pp = pprint.PrettyPrinter(indent=4)


class FileUploadValidationMiddleware(MiddlewareMixin):
    def __init__(self, get_response) -> None:
        self.get_response = get_response
        self.is_async = asyncio.iscoroutinefunction(self.get_response)

    def process_view(
        self, request, view_func, view_args, view_kwargs
    ) -> None | HttpResponse:
        logging.debug(
            "[Middleware][PV] - Processing view: {}".format(view_func.__name__)
        )

        handler = FileUploadHandler()
        config = None

        if hasattr(view_func, "_file_upload_config"):
            logging.debug(
                "[Middleware][PV] - View with name '{}' is file upload wrapped.".format(
                    view_func.__name__
                )
            )
            config = getattr(view_func, "_file_upload_config")
            handler.set_request(request, config)
            logging.debug("[Middleware][PV] - Config:")
            pp.pprint(config)
        else:
            logging.debug(
                "[Middleware][PV] - View with name '{}' is not file upload wrapped.".format(
                    view_func.__name__
                )
            )

        if request.method == "POST" and request.FILES:
            logging.debug("[Middleware][PV] - POST request with files detected.")
            if config:
                logging.debug("[Middleware][PV] - Config detected.")
            else:
                logging.debug("[Middleware][PV] - No config detected.")

            request, files = handler.monitor_request()

            if request.block_request:
                error_response_config = config.get("response_config", {})
                block_message = error_response_config.get(
                    "message", "File upload blocked"
                )
                status = error_response_config.get("status", 403)
                error_func = error_response_config.get(
                    "error_func", HttpResponseForbidden
                )

                if error_response_config.get("redirect_on_block"):
                    logging.debug("[Middleware][PV] - Redirecting request.")
                    messages.add_message(request, messages.ERROR, block_message)
                    redirect_url = reverse(error_response_config["redirect_on_block"])
                    return HttpResponseRedirect(redirect_url)

                logging.debug(
                    "[Middleware][PV] - Blocking request with message: {} and status: {}".format(
                        block_message, status
                    )
                )
                return error_func(block_message, status=status)
            else:
                messages.add_message(
                    request, messages.SUCCESS, "File upload successful."
                )
                request = handler.convert_to_request(files)

        request.file_upload_handler = handler

        return None

    async def __acall__(self, request):
        logging.debug("[Middleware][ACALL] - Before response.")
        response = await self.get_response(request)
        logging.debug("[Middleware][ACALL] - After response.")
        return response

    def __scall__(self, request) -> HttpResponse:
        logging.debug("[Middleware][SCALL] - Before response.")
        response = self.get_response(request)
        logging.debug("[Middleware][SCALL] - After response.")
        return response

    def __call__(self, request) -> Any | HttpResponse:
        logging.debug("[Middleware][CALL] - #############################")
        logging.debug("[Middleware][CALL] - Processing request: {}".format(request))

        response = None

        if self.is_async:
            response = self.__acall__(request)
        else:
            response = self.__scall__(request)

        handler = getattr(request, "file_upload_handler", None)
        if handler:
            response = handler.monitor_response(response)
        else:
            logging.debug("[Middleware][CALL] - No handler in response detected.")

        return response
