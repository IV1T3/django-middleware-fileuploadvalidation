# import ffmpeg
# import logging


# def check_video_integrity(file):
#     logging.debug("[Validation module] - Starting video integrity check")

#     """
#         src: https://ffmpeg.org/ffplay-all.html

#         - crccheck: verifies the CRC checksum of the input video file
#         - bitstream: detects bitstream specification deviations
#         - buffer: detects improper bitstream length
#         - explode: aborts decoding on minor error detection
        
#         optional:
#         - careful: consider things that violate specifications and have not been
#                     seen in the wild as errors
#         - compliant: consider all spec non compliances as errors
#     """

#     # error_detect = "+crccheck+bitstream+buffer+explode+compliant"

#     stream = ffmpeg.input(file.content, **{"loglevel": "error", "threads": 0})
#     stream = stream.output("pipe:", format="null")

#     # BUG: ValueError at /upload/: embedded null byte
#     stdout, stderr = stream.run(capture_stdout=True, capture_stderr=True)
#     return stderr


# def validate_file(file):
#     logging.debug("[Validation module] - Starting video validation")

#     # file.validation_results.file_integrity_ok = check_video_integrity(file)

#     return file
