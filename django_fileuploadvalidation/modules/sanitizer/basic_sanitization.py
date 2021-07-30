import logging
import uuid

def sanitization_task__create_random_filename_with_guessed_extension(
    file_object, file_detection_data
):
    logging.info("[Sanitizer module - Tasks] - Creating random file name")
    file_extension = mime_type_to_file_extension(
        file_detection_data["file"]["guessed_mime"]
    )
    unique_file_name = str(uuid.uuid4()) + file_extension
    file_object.name = unique_file_name

    return file_object