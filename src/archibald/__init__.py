"""Archibald — a prompt-injection detector.

Takes untrusted content apart (text, web pages, forms, PDFs, DOCX, image
metadata), finds the places an instruction could hide, and scores each piece
against a deterministic rule set. It classifies and reports; it never follows,
executes or forwards what it reads.
"""

__version__ = "0.1.0"
