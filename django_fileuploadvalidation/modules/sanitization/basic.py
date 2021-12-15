import logging
import mimetypes
import uuid


def create_random_filename_with_guessed_extension(file_object):
    logging.debug("[Sanitizer module] - Creating random file name")
    file_extension = mimetypes.guess_extension(
        file_object.detection_results.guessed_mime
    )
    unique_file_name = str(uuid.uuid4()) + file_extension
    file_object.basic_information.name = unique_file_name

    return file_object


def sanitize_file(file, upload_config):
    logging.debug("[Sanitizer module] - Starting basic sanitization")

    mimetypes.init()

    if not upload_config["keep_original_filename"]:
        file = create_random_filename_with_guessed_extension(file)
        file.sanitization_results.created_random_filename_with_guessed_extension = True

    return file
