import logging


def evaluate(files, request):
    logging.debug("[Evaluator module] - Starting maliciousness evaluation")

    upload_config = request.upload_config
    block_upload = request.block_request

    sanitization_active = request.upload_config["sanitization"]

    for file_name, file in files.items():
        #############################
        # Handle validation results #
        #############################

        # Always block if strict validation fails
        # If YARA rule matches
        #   Block: if sanitization deactivated
        #   Sanitize and forward: if sanitization activated

        # 1. strict validation - validation
        strict_val_res = [
            file.validation_results.file_size_ok,
            file.validation_results.matching_extension_signature_request_ok,
            file.validation_results.filename_length_ok,
            file.validation_results.extensions_whitelist_ok,
            file.validation_results.request_whitelist_ok,
            file.validation_results.signature_whitelist_ok,
        ]

        # 2. strict validation - attack
        possible_attack_val_res = [
            not file.attack_results.mime_manipulation,
            not file.attack_results.null_byte_injection,
            not file.attack_results.exif_injection,
        ]

        strict_val_success = all(strict_val_res)
        possible_attack_val_success = all(possible_attack_val_res)

        if not (strict_val_success and possible_attack_val_success):
            block_upload = True
            file.block = True
            file.validation_results.malicious = True
            file.append_block_reason("strict_eval_failed")
            logging.warning("[Evaluator module] - Blocking: Strict evaluation FAILED")
        else:
            logging.info("[Evaluator module] - Strict evaluation PASSED")

        # 2. relaxed YARA validation
        yara_val_success = file.validation_results.yara_rules_ok

        if not yara_val_success and not sanitization_active:
            block_upload = True
            file.block = True
            file.validation_results.malicious = True
            file.append_block_reason("yara_eval_failed")
            logging.warning("[Evaluator module] - Blocking: YARA evaluation FAILED")
        else:
            logging.info("[Evaluator module] - YARA evaluation PASSED")

    return files, block_upload
