import logging

from . import basic


def validate(files):
    logging.info("[Validator module] - Starting validation")

    validated_files = {}

    for file_name, file in files.items():

        file = basic.validate_file(file)

        # TODO: Add file type specific validation

        if not file.block:
            validated_files[file_name] = file
        else:
            return None, False

    return validated_files, True
