"""
Init
"""
from __future__ import unicode_literals

import datetime
import os
import subprocess

VERSION = (1, 0, 0, "final", 0)


def get_version(version=None):
    """
    Returns a PEP 386-compliant version number from VERSION.
    """
    if not version:
        version = VERSION
    else:
        assert len(version) == 5
        assert version[3] in ("alpha", "beta", "rc", "final")

    # Now build the two parts of the version number:
    # main = X.Y[.Z]
    # sub = .devN - for pre-alpha releases
    #     | {a|b|c}N - for alpha, beta and rc releases

    parts = 2 if version[2] == 0 else 3
    main = ".".join(str(x) for x in version[:parts])

    sub = ""
    if version[3] == "alpha" and version[4] == 0:
        git_changeset = get_git_changeset()
        if git_changeset:
            sub = ".dev%s" % git_changeset

    elif version[3] != "final":
        mapping = {"alpha": "a", "beta": "b", "rc": "c"}
        sub = mapping[version[3]] + str(version[4])

    return str(main + sub)