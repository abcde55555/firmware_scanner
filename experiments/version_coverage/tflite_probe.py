"""Compatibility entry for the bounded product TensorFlow Lite runtime proof.

The proof is shared with BinaryInventory. It does not recover Maven coordinates
or the LiteRT artifact release from a runtime identifier.
"""

from firmware_scanner.extraction.tflite_version import inspect_elf

__all__ = ["inspect_elf"]
