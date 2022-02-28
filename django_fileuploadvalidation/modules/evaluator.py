import logging


def evaluate(files, request):
    logging.debug("[Evaluator module] - Starting maliciousness evaluation")

    upload_config = request.upload_config
    block_upload = request.block_request

    for file_name, file in files.items():

        #############################
        # Handle validation results #
        #############################

        # 1. strict validation
        strict_val_res = [
            file.validation_results.file_size_ok,
            file.validation_results.matching_extension_signature_request_ok,
            file.validation_results.filename_length_ok,
            file.validation_results.extensions_whitelist_ok,
            file.validation_results.request_whitelist_ok,
            file.validation_results.signature_whitelist_ok,
            file.validation_results.yara_rules_ok
        ]

        strict_val_success = all(strict_val_res)

        if not strict_val_success:
            block_upload = True
            file.block = True
            file.validation_results.malicious = True
            file.append_block_reason("strict_eval_failed")
            logging.warning("[Evaluator module] - Blocking: Strict evaluation FAILED")
        else:
            logging.info("[Evaluator module] - Strict evaluation PASSED")

    return files, block_upload
