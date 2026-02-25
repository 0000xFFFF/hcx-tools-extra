#!/usr/bin/env python3

import re

def rslatin_check(s):
    return bool(re.search(r'[čćšžđČĆŠŽÐ]', s))

def rslatin_replace(s):
    translations = str.maketrans("čćšžđČĆŠŽÐ", "ccszdCCSZD")
    return s.translate(translations)
