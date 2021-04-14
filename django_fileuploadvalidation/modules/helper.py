import re

from ..data.mimetypes import MIME_TYPES


def find_hex_pattern(needle, haystack):
    return [m.start() for m in re.finditer(needle, haystack)]


def fill_hex_with_zero(content, start_idx, end_idx):
    for i in range(start_idx, end_idx):
        content.pop(i)
        content.insert(i, 0)
    return content


def file_extension_to_mime_type(file_extension):
    file_extension = "." + file_extension
    for mime_type_key in MIME_TYPES:
        if file_extension in MIME_TYPES[mime_type_key]:
            return mime_type_key


def mime_type_to_file_extension(mime_type):
    return MIME_TYPES[mime_type][0]