from __future__ import annotations

import hashlib
from typing import BinaryIO


class HashingService:
    BUFFER_SIZE = 1024 * 1024  # 1 MiB chunks

    def compute_sha256(self, stream: BinaryIO) -> str:
        sha256 = hashlib.sha256()
        while chunk := stream.read(self.BUFFER_SIZE):
            sha256.update(chunk)
        stream.seek(0)
        return sha256.hexdigest()

    def create_digest(self) -> hashlib._Hash:
        return hashlib.sha256()
