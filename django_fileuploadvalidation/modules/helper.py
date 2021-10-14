import re


def find_hex_pattern(needle, haystack):
    return [m.start() for m in re.finditer(needle, haystack)]


def fill_hex_with_zero(content, start_idx, end_idx):
    for i in range(start_idx, end_idx):
        content.pop(i)
        content.insert(i, 0)
    return content


def add_point_to_guessed_file_type(file, mime):
    if mime in file.validation_results.guessing_scores:
        file.validation_results.guessing_scores[mime] += 1
    else:
        file.validation_results.guessing_scores[mime] = 1

    file.validation_results.total_points_overall += 1

    return file
