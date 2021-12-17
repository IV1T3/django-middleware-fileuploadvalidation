import logging


def evaluate(files, upload_config):
    logging.debug("[Evaluator module] - Starting maliciousness evaluation")

    block_upload = False

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

        # 2. vague validation
        if not block_upload:

            max_mal_score = 0.0

            vague_val_mal_score = 0.0
            vague_val_weights = {
                "integrity": 1.0,
                "keywords": 1.0,
                "pdf_check": 1.5,
                "office_macros": 1.0,
            }

            keyword_weights = {
                # "<?": [],
                "<?=": [],
                "<?php": [],
                # "?> ": [],
                "<script": [],
                # "#!": [],
                "#!/": [],
                "#!/bin/sh": [],
                "#!/bin/bash": [],
                "#!/usr/bin/pwsh": [],
                "#!/usr/bin/env python3": [],
                "#!/usr/bin/env sh": [],
                # "$_": [],
                "base64": [],
                "eval": [],
            }

            # 2.1. Evaluate found keywords
            # TODO: Use weight based on keyword maliciousness
            keywords_score_outcome = [1.0 * vague_val_weights["keywords"], 0.0]
            factor_number_of_key_occurences = 0.0
            if not file.validation_results.keyword_search_ok:
                logging.info("[Evaluator module] - Starting keyword analysis")
                for key, values in file.detection_results.found_keywords.items():
                    factor_number_of_key_occurences += len(values)

                vague_val_mal_score += (
                    keywords_score_outcome[0] * factor_number_of_key_occurences
                )

            max_mal_score += (
                keywords_score_outcome[
                    keywords_score_outcome[0] < keywords_score_outcome[1]
                ]
                * factor_number_of_key_occurences
            )

            # 2.2. Evaluate file integrity
            if file.validation_results.file_integrity_check_done:
                logging.info("[Evaluator module] - Starting file integrity analysis")
                integrity_score_outcomes = [1.0 * vague_val_weights["integrity"], 0.0]

                if not file.validation_results.file_integrity_ok:
                    vague_val_mal_score += integrity_score_outcomes[
                        file.validation_results.file_integrity_ok
                    ]

                max_mal_score += integrity_score_outcomes[
                    integrity_score_outcomes[0] < integrity_score_outcomes[1]
                ]

            if max_mal_score != 0:
                normalized_maliciousness = vague_val_mal_score / max_mal_score

                if normalized_maliciousness > 1 - upload_config["sensitivity"]:
                    logging.warning(
                        "[Evaluator module] - Blocking: Vague evaluation FAILED"
                    )
                    block_upload = True
                    file.block = True
                    file.append_block_reason("vague_eval_failed")
                    file.validation_results.malicious = True
                else:
                    logging.info("[Evaluator module] - Vague evaluation PASSED")
        else:
            break

    return files, block_upload
