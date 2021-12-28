import json
import logging
import os
import time

import pprint

pp = pprint.PrettyPrinter(indent=4)


def convert(nested_dict):
    """
    Convert nested dict with bytes to str.
    This is needed because bytes are not JSON serializable.

    :param nested_dict: nested dict with bytes
    """
    if isinstance(nested_dict, dict):
        return {convert(k): convert(v) for k, v in nested_dict.items()}
    elif isinstance(nested_dict, list):
        return [convert(v) for v in nested_dict]
    elif isinstance(nested_dict, tuple):
        return tuple(convert(v) for v in nested_dict)
    elif (
        isinstance(nested_dict, str)
        or isinstance(nested_dict, int)
        or isinstance(nested_dict, float)
    ):
        return nested_dict
    else:
        return str(nested_dict)


def create_file_path(filename, mode):
    logging.debug("[Reporter module] - Creating file path")
    curr_time = time.time()
    report_name = str(curr_time) + "_" + filename + ".json"
    file_path = f"./uploadlogs/{mode}/{report_name}"
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    return file_path


def prepare_json_data(files):
    logging.debug("[Reporter module] - Preparing json data")
    json_data = {}
    for file_name, file in files.items():
        json_data[file_name] = {}

        json_data[file_name]["overview"] = {
            "name": file.basic_information.name,
            "size": file.basic_information.size,
            "content_type": file.basic_information.content_type,
            "charset": file.basic_information.charset,
            "md5": file.basic_information.md5,
            "sha1": file.basic_information.sha1,
            "sha256": file.basic_information.sha256,
            "sha512": file.basic_information.sha512,
            "block": file.block,
            "block_reasons": file.block_reasons,
        }

        json_data[file_name]["detection"] = {
            "filename_splits": file.detection_results.filename_splits,
            "extensions": file.detection_results.extensions,
            "signature_mime": file.detection_results.signature_mime,
            "guessed_mime": file.detection_results.guessed_mime,
        }

        file.validation_results.guessing_scores = {
            k: v for k, v in file.validation_results.guessing_scores.items() if v > 0
        }

        json_data[file_name]["evaluation"] = {
            "mime_manipulation": file.attack_results.mime_manipulation,
            "null_byte_injection": file.attack_results.null_byte_injection,
            "exif_injection": file.attack_results.exif_injection,
        }

        # Add Quicksand results
        if file.quicksand_results["results"]:
            json_data[file_name]["quicksand"] = {}
            for suspicious_finding in file.quicksand_results["results"]["root"]:
                json_data[file_name]["quicksand"][suspicious_finding["rule"]] = {
                    "description": suspicious_finding["desc"],
                    "strings": suspicious_finding["strings"],
                    "type": suspicious_finding["type"],
                }

                if "mitre" in suspicious_finding:
                    json_data[file_name]["quicksand"][suspicious_finding["rule"]][
                        "mitre"
                    ] = suspicious_finding["mitre"]

            json_data[file_name]["quicksand"]["score"] = file.quicksand_results["score"]
            json_data[file_name]["quicksand"]["warning"] = file.quicksand_results[
                "warning"
            ]
            json_data[file_name]["quicksand"]["exploit"] = file.quicksand_results[
                "exploit"
            ]
            json_data[file_name]["quicksand"]["execute"] = file.quicksand_results[
                "execute"
            ]
            json_data[file_name]["quicksand"]["feature"] = file.quicksand_results[
                "feature"
            ]
            json_data[file_name]["quicksand"]["risk"] = file.quicksand_results["risk"]
            json_data[file_name]["quicksand"]["rating"] = file.quicksand_results[
                "rating"
            ]
            json_data[file_name]["quicksand"]["structhash"] = file.quicksand_results[
                "structhash"
            ]
            json_data[file_name]["quicksand"]["structure"] = file.quicksand_results[
                "structure"
            ]

        json_data[file_name]["validation_results"] = file.validation_results.__dict__
        json_data[file_name][
            "sanitization_results"
        ] = file.sanitization_results.__dict__

    json_data = convert(json_data)

    return json_data


def write_json(json_data, file_path):
    with open(file_path, "w") as f:
        json.dump(json_data, f, indent=4)


def build_report(files):
    logging.debug("[Reporter module] - Building report")

    for _, file in files.items():
        file_upload_mode = "blocked" if file.block else "success"
        file_path = create_file_path(file.basic_information.name, file_upload_mode)
        json_data = prepare_json_data(files)
        write_json(json_data, file_path)
