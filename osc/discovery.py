# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Fannandya
# Part of OSC (Open Source Code Scanner) - https://github.com/Fannandya/security-checker

"""Aggressive content discovery: wordlist-based path brute-forcing.

Generates candidate URLs from a wordlist. The scanner fetches them through the
normal, soft-404-aware pipeline, so brute-forced 200s on catch-all sites do NOT
become false positives.
"""

import os
from urllib.parse import urljoin

# Extensions appended to bare wordlist entries (those without their own extension).
DEFAULT_EXTENSIONS = (
    'php', 'html', 'txt', 'bak', 'old', 'backup', 'zip', 'tar.gz',
    'sql', 'json', 'env', 'log', 'yml', 'yaml', 'ini', 'config', 'swp', 'save',
)


def default_wordlist_path():
    """Path to the bundled wordlist shipped inside the package."""
    return os.path.join(os.path.dirname(__file__), 'wordlists', 'common.txt')


def load_wordlist(path=None):
    """Load words from `path` (or the bundled wordlist). Blank/`#` lines ignored."""
    path = path or default_wordlist_path()
    words = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                word = line.strip()
                if word and not word.startswith('#'):
                    words.append(word)
    except Exception:
        pass
    return words


def generate_bruteforce_urls(base_url, words, extensions=None):
    """Build a set of candidate URLs from `words`.

    For an entry that already has an extension (contains a dot in its last
    segment) it is used as-is. For a bare name we also try a directory variant
    (`name/`) and each configured extension (`name.ext`).
    """
    base = base_url.rstrip('/') + '/'
    exts = [e.strip().lstrip('.') for e in (extensions or DEFAULT_EXTENSIONS) if e and e.strip()]
    urls = set()
    for raw in words:
        word = raw.strip().lstrip('/')
        if not word or word.startswith('#'):
            continue
        urls.add(urljoin(base, word))
        last_segment = word.rsplit('/', 1)[-1]
        if '.' not in last_segment:  # bare name -> try dir + extension permutations
            urls.add(urljoin(base, word + '/'))
            for ext in exts:
                urls.add(urljoin(base, f'{word}.{ext}'))
    return urls
