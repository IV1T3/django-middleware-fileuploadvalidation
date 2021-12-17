import logging

from quicksand.quicksand import quicksand


def perform_quicksand_scan(file):
    logging.debug("[Validation module] - Running Quicksand")

    qs = quicksand(file.content, timeout=18, strings=True)
    qs.process()

    file.quicksand_results = qs.results

    if qs.results["score"] > 0:
        file.block = True
        file.append_block_reason("QS_detection")
        logging.warning(
            f"{file.basic_information.name} [Validation module] - Blocking file: Quicksand detection"
        )

    return file


def validate_file(file, upload_config):
    logging.debug("[Validation module] - Starting Quicksand")

    file = perform_quicksand_scan(file)

    return file
