from django.core.handlers.wsgi import WSGIRequest
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.http import QueryDict
from django.utils.datastructures import MultiValueDict

from io import BytesIO

import logging

from .. import File


def build_post(original_post):
    logging.debug("[Converter module] - Building POST")
    new_post = QueryDict(mutable=True)
    new_post.update({"csrfmiddlewaretoken": original_post.get("csrfmiddlewaretoken")})
    new_post.update({"title": original_post.get("title")})

    return new_post


def build_files(sanitized_file_objects):
    logging.debug("[Converter module] - Building FILES")
    all_files_MultiValueDict = MultiValueDict()

    for key in sanitized_file_objects:
        sanitized_file_object = sanitized_file_objects[key]
        sanitized_imuf = build_InMemoryUploadedFile(sanitized_file_object)
        all_files_MultiValueDict.appendlist("file", sanitized_imuf)

    return all_files_MultiValueDict


def build_InMemoryUploadedFile(sanitized_file_object):
    logging.debug("[Converter module] - Building InMemoryUploadedFile")

    file_imuf = InMemoryUploadedFile(
        BytesIO(sanitized_file_object.content),
        "file",
        sanitized_file_object.basic_information.name,
        sanitized_file_object.basic_information.content_type,
        sanitized_file_object.basic_information.size,
        sanitized_file_object.basic_information.charset,
        sanitized_file_object.basic_information.content_type_extra,
    )

    return file_imuf


def request_to_base_file_objects(request_files):
    logging.debug("[Converter module - Basic] - Starting request to File objects")
    file_objects = {}
    for file_key in request_files:
        request_file = request_files[file_key]
        file_objects[request_file.name] = File.File(request_file)
    return file_objects


def file_objects_to_request(original_request, sanitized_file_objects):
    logging.debug("[Converter module] - Starting file objects to request")

    sanitized_request = WSGIRequest(original_request.environ)

    # logging.debug(original_request.__dict__.keys())
    # dict_keys(['environ', 'path_info', 'path', 'META', 'method', 'content_type', 'content_params', '_stream', '_read_started',
    # 'resolver_match', 'COOKIES', 'session', 'user', '_messages', '_body', '_upload_handlers', '_post', '_files'])

    sanitized_post_for_request = build_post(original_request.__dict__["_post"])
    sanitized_files_for_request = build_files(sanitized_file_objects)

    setattr(sanitized_request, "_post", sanitized_post_for_request)
    setattr(sanitized_request, "_files", sanitized_files_for_request)

    for file_key in sanitized_file_objects:
        file_object = sanitized_file_objects[file_key]
        logging.debug(f"[Converter module] - {file_object=} - {sanitized_request}")

    return sanitized_request
