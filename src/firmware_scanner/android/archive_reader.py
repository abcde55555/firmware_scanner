"""Seekable read-only access to archived files inside filesystem images."""
from __future__ import annotations

import io
import os


class FilesystemFile(io.RawIOBase):
    """Expose bounded random reads so ZIP directories need no full APK buffer."""

    MAX_READ = 64 * 1024 * 1024

    def __init__(self, filesystem, path: str):
        super().__init__()
        if not callable(getattr(filesystem, 'read_file_range', None)):
            raise TypeError('filesystem does not support random-access reads')
        self._filesystem = filesystem
        self._path = path
        self._size = filesystem.file_size(path)
        self._position = 0

    def readable(self):
        return not self.closed

    def seekable(self):
        return not self.closed

    def tell(self):
        self._checkClosed()
        return self._position

    def seek(self, offset, whence=os.SEEK_SET):
        self._checkClosed()
        if whence == os.SEEK_CUR:
            offset += self._position
        elif whence == os.SEEK_END:
            offset += self._size
        elif whence != os.SEEK_SET:
            raise ValueError('invalid whence')
        if offset < 0:
            raise ValueError('negative seek position')
        self._position = offset
        return offset

    def read(self, size=-1):
        self._checkClosed()
        available = max(0, self._size - self._position)
        size = available if size is None or size < 0 else min(size, available)
        if size > self.MAX_READ:
            raise OSError('filesystem archive read exceeds 64 MiB budget')
        if not size:
            return b''
        data = self._filesystem.read_file_range(self._path, self._position, size)
        if data is None or len(data) != size:
            raise OSError('truncated filesystem archive read')
        self._position += len(data)
        return data

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)
