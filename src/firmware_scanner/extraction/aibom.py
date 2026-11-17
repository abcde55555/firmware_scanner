"""AI Bill of Materials (AIBOM) scanner for embedded firmware.

Identifies machine learning model files (TensorFlow Lite, GGUF, ONNX, ExecuTorch, RKNN, MNN)
and embedded inference runtimes (TFLite Micro, CMSIS-NN, ONNX Runtime, llama.cpp).
Outputs standardized CycloneDX 1.6 `machine-learning-model` components.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class ModelFormatDef:
    key: str
    name: str
    suffixes: tuple[str, ...]
    magic: Optional[tuple[int, bytes]] = None
    note: str = ""


MODEL_FORMATS: tuple[ModelFormatDef, ...] = (
    ModelFormatDef("gguf", "GGUF", (".gguf",), (0, b"GGUF")),
    ModelFormatDef("tflite", "TensorFlow Lite", (".tflite",), (4, b"TFL3")),
    ModelFormatDef("executorch", "ExecuTorch", (".pte",), (4, b"ET12")),
    ModelFormatDef("onnx", "ONNX", (".onnx",)),
    ModelFormatDef("safetensors", "safetensors", (".safetensors",)),
    ModelFormatDef("pytorch", "PyTorch checkpoint", (".pt", ".pth", ".ckpt"), note="Pickle-based checkpoint"),
    ModelFormatDef("rknn", "Rockchip RKNN", (".rknn",)),
    ModelFormatDef("mnn", "Alibaba MNN", (".mnn",)),
)

# Embedded TFLite flatbuffer compiled as C array: 0x54, 0x46, 0x4c, 0x33
EMBEDDED_TFLITE_RE = re.compile(rb"0x54\s*,\s*0x46\s*,\s*0x4[cC]\s*,\s*0x33")

_B = r"(?<![A-Za-z0-9_])"


@dataclass(frozen=True)
class RuntimeDef:
    key: str
    name: str
    patterns: tuple[str, ...]


RUNTIMES: tuple[RuntimeDef, ...] = (
    RuntimeDef("tflite-micro", "TensorFlow Lite Micro", (
        _B + r"(?:tflite::MicroInterpreter|tflite::MicroMutableOpResolver|tensorflow/lite/micro/\w+)",
    )),
    RuntimeDef("tflite", "TensorFlow Lite", (
        _B + r"(?:TfLiteInterpreter\w*|tflite::Interpreter\b|tflite::FlatBufferModel)",
    )),
    RuntimeDef("onnxruntime", "ONNX Runtime", (
        _B + r"(?:OrtCreateSession\w*|onnxruntime_c_api\.h|Ort::Session|OrtGetApiBase)",
    )),
    RuntimeDef("cmsis-nn", "CMSIS-NN", (
        _B + r"(?:arm_convolve_s8|arm_convolve_s16|arm_fully_connected_s8|arm_nn_\w+)",
    )),
    RuntimeDef("llama-cpp", "llama.cpp / ggml", (
        _B + r"(?:llama_model_load\w*|llama_init_from_\w+|ggml_init\b|gguf_init_from_file)",
    )),
    RuntimeDef("executorch", "ExecuTorch", (
        _B + r"(?:executorch::\w+|executorch/runtime/\w+)",
    )),
    RuntimeDef("nnom", "NNoM", (
        _B + r"(?:nnom_model_create|nnom_model_run|nnom\.h)",
    )),
)


@dataclass
class DiscoveredAIModel:
    name: str
    format_key: str
    format_name: str
    file_path: str
    size_bytes: int = 0
    sha256: str = ""
    evidence: str = ""
    note: str = ""


@dataclass
class DiscoveredAIRuntime:
    runtime_key: str
    runtime_name: str
    binary_path: str
    evidence: str = ""


class AIBOMScanner:
    """Scans firmware filesystem trees and binaries for ML models and runtimes."""

    def __init__(self):
        self._compiled_runtimes = [
            (rt, [re.compile(p.encode("ascii", errors="ignore")) for p in rt.patterns])
            for rt in RUNTIMES
        ]

    def scan_file_header(self, filename: str, head_bytes: bytes, file_size: int = 0) -> Optional[DiscoveredAIModel]:
        """Check if file header or extension matches an embedded ML model."""
        fn_lower = filename.lower()

        for fmt in MODEL_FORMATS:
            # Suffix match
            suffix_matched = any(fn_lower.endswith(sfx) for sfx in fmt.suffixes)

            # Magic bytes match
            magic_matched = False
            if fmt.magic and len(head_bytes) >= fmt.magic[0] + len(fmt.magic[1]):
                offset, magic = fmt.magic
                if head_bytes[offset:offset + len(magic)] == magic:
                    magic_matched = True

            if suffix_matched or magic_matched:
                evidence = f"Magic bytes {fmt.magic[1]!r}" if magic_matched else f"File extension {fn_lower.split('.')[-1]}"
                return DiscoveredAIModel(
                    name=filename.rsplit("/", 1)[-1],
                    format_key=fmt.key,
                    format_name=fmt.name,
                    file_path=filename,
                    size_bytes=file_size,
                    evidence=evidence,
                    note=fmt.note,
                )

        # Check for embedded TFLite array in binary / source code
        if EMBEDDED_TFLITE_RE.search(head_bytes):
            return DiscoveredAIModel(
                name=filename.rsplit("/", 1)[-1],
                format_key="tflite",
                format_name="TensorFlow Lite (Embedded Array)",
                file_path=filename,
                size_bytes=file_size,
                evidence="Embedded TFLite C array (0x54, 0x46, 0x4c, 0x33)",
            )

        return None

    def scan_binary_for_runtimes(self, filename: str, data: bytes) -> list[DiscoveredAIRuntime]:
        """Scan binary contents for AI inference runtimes."""
        results: list[DiscoveredAIRuntime] = []
        chunk = data[:4 * 1024 * 1024]

        for rt, regexes in self._compiled_runtimes:
            for r in regexes:
                match = r.search(chunk)
                if match:
                    results.append(
                        DiscoveredAIRuntime(
                            runtime_key=rt.key,
                            runtime_name=rt.name,
                            binary_path=filename,
                            evidence=f"API signature: {match.group(0).decode('ascii', errors='replace')}",
                        )
                    )
                    break

        return results

    def to_components(
        self, models: list[DiscoveredAIModel], runtimes: list[DiscoveredAIRuntime]
    ) -> list[Any]:
        """Convert discovered AI models and runtimes to native Component objects."""
        from .models import Component, VersionConfidence, ExtractionMethod
        comps: list[Component] = []

        for m in models:
            props = [
                {"name": "ai:modelFormat", "value": m.format_name},
                {"name": "ai:filePath", "value": m.file_path},
            ]
            if m.evidence:
                props.append({"name": "ai:evidence", "value": m.evidence})
            if m.note:
                props.append({"name": "ai:note", "value": m.note})

            c = Component(
                name=m.name,
                component_type="machine-learning-model",
                resolved_version="",
                description=f"Embedded ML model: {m.format_name} at {m.file_path}",
                model_card={
                    "modelParameters": {
                        "approach": {"type": "supervised"},
                    },
                },
                properties=props,
                versions=[VersionConfidence(
                    version="detected",
                    confidence=0.95,
                    method=ExtractionMethod.BINARY_SIGNATURE,
                    evidence=m.evidence or f"Found at {m.file_path}",
                )],
            )
            comps.append(c)

        for rt in runtimes:
            c_rt = Component(
                name=rt.runtime_name,
                component_type="library",
                resolved_version="",
                description=f"Embedded AI inference engine: {rt.runtime_name}",
                properties=[
                    {"name": "ai:runtimeKey", "value": rt.runtime_key},
                    {"name": "ai:location", "value": rt.binary_path},
                    {"name": "ai:evidence", "value": rt.evidence},
                ],
                versions=[VersionConfidence(
                    version="detected",
                    confidence=0.90,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=rt.evidence,
                )],
            )
            comps.append(c_rt)

        return comps

    def to_cyclonedx_components(
        self, models: list[DiscoveredAIModel], runtimes: list[DiscoveredAIRuntime]
    ) -> list[dict[str, Any]]:
        """Convert discovered AI models and runtimes to CycloneDX 1.6 components."""
        cdx_components: list[dict[str, Any]] = []

        # Convert Models
        for m in models:
            props = [
                {"name": "ai:modelFormat", "value": m.format_name},
                {"name": "ai:filePath", "value": m.file_path},
            ]
            if m.evidence:
                props.append({"name": "ai:evidence", "value": m.evidence})
            if m.note:
                props.append({"name": "ai:note", "value": m.note})

            comp: dict[str, Any] = {
                "type": "machine-learning-model",
                "name": m.name,
                "description": f"Embedded ML model: {m.format_name}",
                "modelCard": {
                    "modelParameters": {
                        "approach": {"type": "supervised"},
                    },
                },
                "properties": props,
            }
            cdx_components.append(comp)

        # Convert Runtimes
        for rt in runtimes:
            comp_rt: dict[str, Any] = {
                "type": "library",
                "name": rt.runtime_name,
                "description": f"Embedded AI inference engine: {rt.runtime_name}",
                "properties": [
                    {"name": "ai:runtimeKey", "value": rt.runtime_key},
                    {"name": "ai:location", "value": rt.binary_path},
                    {"name": "ai:evidence", "value": rt.evidence},
                ],
            }
            cdx_components.append(comp_rt)

        return cdx_components
