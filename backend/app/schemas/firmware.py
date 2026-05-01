import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, model_validator


FirmwareKind = Literal["linux", "rtos", "unknown"]
FirmwareKindSource = Literal["detected", "manual"]
RtosFlavor = Literal["freertos", "zephyr", "baremetal-cortexm"]


class FirmwareUploadResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    version_label: str | None = None
    firmware_kind: FirmwareKind = "unknown"
    firmware_kind_source: FirmwareKindSource | None = None
    rtos_flavor: RtosFlavor | None = None
    created_at: datetime


class FirmwareUpdate(BaseModel):
    version_label: str | None = None


class FirmwareKindUpdate(BaseModel):
    kind: FirmwareKind
    rtos_flavor: RtosFlavor | None = None

    @model_validator(mode="after")
    def _flavor_only_for_rtos(self) -> "FirmwareKindUpdate":
        if self.kind != "rtos" and self.rtos_flavor is not None:
            raise ValueError("rtos_flavor may only be set when kind == 'rtos'")
        return self


class FirmwareDetailResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    storage_path: str | None
    extracted_path: str | None
    extraction_dir: str | None = None
    architecture: str | None
    endianness: str | None
    os_info: str | None
    kernel_path: str | None
    version_label: str | None = None
    firmware_kind: FirmwareKind = "unknown"
    firmware_kind_source: FirmwareKindSource | None = None
    rtos_flavor: RtosFlavor | None = None
    unpack_log: str | None
    created_at: datetime


# ── Firmware Image Metadata schemas ──


class FirmwareSectionResponse(BaseModel):
    offset: int
    size: int | None
    type: str
    description: str


class UBootHeaderResponse(BaseModel):
    magic: str
    header_crc: str
    timestamp: int
    data_size: int
    load_address: str
    entry_point: str
    data_crc: str
    os_type: str
    architecture: str
    image_type: str
    compression: str
    name: str


class MTDPartitionResponse(BaseModel):
    name: str
    offset: int | None
    size: int


class FirmwareMetadataResponse(BaseModel):
    file_size: int
    sections: list[FirmwareSectionResponse] = []
    uboot_header: UBootHeaderResponse | None = None
    uboot_env: dict[str, str] = {}
    mtd_partitions: list[MTDPartitionResponse] = []
