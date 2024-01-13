# TODO - Implement the following:
# Temporary Storage Configuration: Configure how and where to temporarily store files during processing.
# Quota Limits: Set limits on the number of uploads or total upload volume per user/session.
# Error Handling Options: Define how to handle errors (e.g., raise exception, return specific HTTP response).
# Custom Validation Function: Allow a custom validation function to be passed.
# File Content Inspection: Enable or disable content inspection for security.

from typing import List

def file_upload_config(**config_options):
    default_config: dict[str, bool | str | List | None] = {
        "clamav": False,
        "file_size_limit": None,
        "filename_length_limit": None,
        "keep_original_filename": False,
        "sanitization": True,
        "uploadlogs_mode": "blocked",
        "whitelist_name": "RESTRICTED",
        "whitelist": [],
    }

    default_config.update(config_options)

    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):

            setattr(request, "_file_upload_config", default_config)

            return view_func(request, *args, **kwargs)
        _wrapped_view._file_upload_config = default_config
        return _wrapped_view
    return decorator