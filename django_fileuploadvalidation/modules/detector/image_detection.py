import logging


def check_file_exif_data(file_object, detection_data):
    logging.info("[Image Detector module] - Getting exif data")
    exif_data = file_object.exif_data
    # logging.debug(f"[Detector module] - {exif_data=}")
    # TODO: Add detection of exif injection
    malicious_injections = ["<?", "<script>", "$_", "base64", "eval"]
    for malicious_injection in malicious_injections:
        if malicious_injection in exif_data:
            detection_data["recognized_attacks"]["exif_injection"] = True
            break

    if len(exif_data) > 0:
        detection_data["sanitization_tasks"]["clean_exif"] = True

    return detection_data


def run_image_detection(image_file_objects, images_detection_data):
    logging.info("[Image Detector module] - Starting image detection")

    for file_obj_key, file_obj in image_file_objects.items():

        image_detection_data = images_detection_data[file_obj_key]

        image_detection_data["file"]["exif"] = check_file_exif_data(
            file_obj, image_detection_data
        )

    return images_detection_data
