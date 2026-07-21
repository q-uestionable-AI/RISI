"""Memory-adapter interfaces and reference implementations."""

from risi.adapters.base import MemoryAdapter
from risi.adapters.dify import DifyKnowledgeAdapter
from risi.adapters.external import (
    ExternalKnowledgeAdapter,
    ExternalTargetManifest,
    credential_pbkdf2_sha256,
)
from risi.adapters.reference import ReferenceMemoryAdapter

__all__ = [
    "DifyKnowledgeAdapter",
    "ExternalKnowledgeAdapter",
    "ExternalTargetManifest",
    "MemoryAdapter",
    "ReferenceMemoryAdapter",
    "credential_pbkdf2_sha256",
]
