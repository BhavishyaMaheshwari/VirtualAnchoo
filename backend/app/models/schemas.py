from typing import Literal
from pydantic import BaseModel, Field, field_validator
from ..core.config import MAX_PACKETS

class CaptureStart(BaseModel):
    interface: str = Field(min_length=1, max_length=128)
    bpf_filter: str = Field(default="", max_length=1024)
    packet_limit: int = Field(default=10000, ge=1, le=MAX_PACKETS)
    authorized: Literal[True]

    @field_validator("interface", "bpf_filter")
    @classmethod
    def no_control_characters(cls, value):
        if any(ord(c) < 32 for c in value):
            raise ValueError("Control characters are not allowed")
        return value
