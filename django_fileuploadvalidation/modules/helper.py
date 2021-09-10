import re


def find_hex_pattern(needle, haystack):
    return [m.start() for m in re.finditer(needle, haystack)]


def fill_hex_with_zero(content, start_idx, end_idx):
    for i in range(start_idx, end_idx):
        content.pop(i)
        content.insert(i, 0)
    return content