import logging
import mimetypes
import uuid


def sanitization_task__create_random_filename_with_guessed_extension(file_object):
    logging.info("[Sanitizer module - Basic] - TASK: Creating random file name")
    file_extension = mimetypes.guess_extension(
        file_object.detection_results.guessed_mime
    )
    unique_file_name = str(uuid.uuid4()) + file_extension
    file_object.basic_information.name = unique_file_name

    return file_object


def iterate_sanitization_tasks(file_object):
    logging.info("[Sanitizer module - Basic] - Starting sanitization tasks")
    file_object = sanitization_task__create_random_filename_with_guessed_extension(
        file_object
    )
    file_object.sanitization_results.created_random_filename_with_guessed_extension = (
        True
    )
    return file_object


def run_sanitization(converted_file_objects):
    logging.info("[Sanitizer module - Basic] - Starting sanitization")

    all_sanitized_file_objects = {}

    for file_object_key in converted_file_objects:
        sanitized_file_object = iterate_sanitization_tasks(
            converted_file_objects[file_object_key]
        )

        all_sanitized_file_objects[file_object_key] = sanitized_file_object

    return all_sanitized_file_objects
