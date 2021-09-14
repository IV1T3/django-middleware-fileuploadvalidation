import logging


def check_file_exif_data(file_obj):
    logging.info("[Image Detector module] - Getting exif data")
    exif_data = file_obj.basic_information.exif_data
    # logging.debug(f"[Detector module] - {exif_data=}")
    # TODO: Add detection of exif injection
    malicious_injections = ["<?", "<script>", "$_", "base64", "eval"]
    for malicious_injection in malicious_injections:
        if malicious_injection in exif_data:
            logging.warning(
                f"[Detector module] - {malicious_injection} found in exif data"
            )
            file_obj.attack_results.exif_injection = True
            file_obj.block = True
            file_obj.append_block_reason("exif_injection")
            # detection_data["recognized_attacks"]["exif_injection"] = True
            break

    # if len(exif_data) > 0:
    #    detection_data["sanitization_tasks"]["clean_exif"] = True

    return file_obj


def run_image_detection(image_file_objects):
    logging.info("[Image Detector module] - Starting image detection")

    for file_obj_key, file_obj in image_file_objects.items():

        # image_detection_data = images_detection_data[file_obj_key]

        image_file_objects[file_obj_key] = check_file_exif_data(file_obj)

        # image_detection_data["file"]["exif"] = check_file_exif_data(
        #    file_obj, image_detection_data
        # )

    return image_file_objects
