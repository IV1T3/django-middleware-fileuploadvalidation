import logging

from pdfid import pdfid


def sanitize_file(file):
    logging.debug("[Sanitizer module] - Starting application sanitization")

    if file.detection_results.guessed_mime == "application/pdf":
        try:
            options = pdfid.get_fake_options()
            options.disarm = True
            options.return_disarmed_buffer = True

            disarmed_pdf_dict = pdfid.PDFiDMain(
                ["unsanitized.pdf"], options, [file.content]
            )

            file.content = disarmed_pdf_dict["buffers"][0]
            file.sanitization_results.disarmed_pdf = True

        except Exception as e:
            logging.debug("[Sanitizer module - PDF] - PDF parsing failed: {}".format(e))

    return file
