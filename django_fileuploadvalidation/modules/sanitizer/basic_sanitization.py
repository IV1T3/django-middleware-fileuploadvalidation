import logging
import mimetypes
import uuid

# from ...data.filesanitizationdata import FILE_SANITITAZION_DATA_TEMPLATE


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
    # file_sanitization_data = FILE_SANITITAZION_DATA_TEMPLATE
    # file_sanitization_tasks = file_detection_data["sanitization_tasks"]

    # if file_sanitization_tasks["start_sanitization"]:
    #     if file_sanitization_tasks["create_random_filename_with_guessed_extension"]:
    file_object = sanitization_task__create_random_filename_with_guessed_extension(
        file_object
    )
    file_object.sanitization_results.created_random_filename_with_guessed_extension = (
        True
    )
    # file_sanitization_data[
    #    "created_random_filename_with_guessed_extension"
    # ] = True

    # return file_sanitization_data, file_object
    return file_object


def run_sanitization(converted_file_objects):
    logging.info("[Sanitizer module - Basic] - Starting sanitization")

    # all_sanitized_data = {}
    all_sanitized_file_objects = {}

    for file_object_key in converted_file_objects:
        # file_sanitization_data, sanitized_file_object = iterate_sanitization_tasks(
        #    converted_file_objects[file_object],
        #    detection_data[file_object],
        # )

        sanitized_file_object = iterate_sanitization_tasks(
            converted_file_objects[file_object_key]
        )

        # all_sanitized_data[file_object] = file_sanitization_data
        all_sanitized_file_objects[file_object_key] = sanitized_file_object

    # return all_sanitized_data, all_sanitized_file_objects
    return all_sanitized_file_objects
