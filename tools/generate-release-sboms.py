#!/usr/bin/env python3
"""Generate deterministic CycloneDX 1.6 SBOMs from every classified lockfile."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKSPACES = (
    ("production", "Cargo.lock"),
    ("verification", "verification/Cargo.lock"),
    ("fuzz", "fuzz/Cargo.lock"),
    ("migration", "migration/legacy-xchacha20poly1305/Cargo.lock"),
    ("bench", "tools/bench-processor/Cargo.lock"),
)


class SbomError(RuntimeError):
    pass


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def component_ref(package: dict) -> str:
    source = package.get("source", "local")
    checksum = package.get("checksum", "none")
    return f"pkg:cargo/{package['name']}@{package['version']}?source={sha256(source.encode())[:16]}&checksum={checksum}"


def build_sbom(workspace: str, lock_relative: str) -> bytes:
    lock_path = ROOT / lock_relative
    raw = lock_path.read_bytes()
    lock = tomllib.loads(raw.decode("utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise SbomError(f"{lock_relative} has no package closure")
    refs = {(row["name"], row["version"], row.get("source")): component_ref(row) for row in packages}
    components = []
    dependencies = []
    for row in sorted(packages, key=lambda item: (item["name"], item["version"], item.get("source", ""))):
        ref = component_ref(row)
        component = {
            "bom-ref": ref,
            "name": row["name"],
            "type": "library",
            "version": row["version"],
        }
        if "checksum" in row:
            component["hashes"] = [{"alg": "SHA-256", "content": row["checksum"]}]
        if "source" in row:
            component["properties"] = [{"name": "cargo:source", "value": row["source"]}]
        components.append(component)
        depends_on = []
        for dependency in row.get("dependencies", []):
            name_version = dependency.split()
            candidates = [value for (name, version, _source), value in refs.items() if name == name_version[0] and (len(name_version) == 1 or version == name_version[1])]
            depends_on.extend(candidates)
        dependencies.append({"dependsOn": sorted(set(depends_on)), "ref": ref})
    document = {
        "bomFormat": "CycloneDX",
        "components": components,
        "dependencies": dependencies,
        "metadata": {
            "component": {"name": f"dcrypt-{workspace}-workspace", "type": "application", "version": "4.0.0"},
            "properties": [
                {"name": "dcrypt:lock-path", "value": lock_relative},
                {"name": "dcrypt:lock-sha256", "value": sha256(raw)},
                {"name": "dcrypt:evidence-class", "value": "deterministic-first-party-sbom"},
            ],
            "tools": {"components": [{"name": "generate-release-sboms.py", "type": "application", "version": "1"}]},
        },
        "serialNumber": f"urn:uuid:{sha256((workspace + sha256(raw)).encode())[:8]}-{sha256((workspace + sha256(raw)).encode())[8:12]}-4{sha256((workspace + sha256(raw)).encode())[13:16]}-8{sha256((workspace + sha256(raw)).encode())[17:20]}-{sha256((workspace + sha256(raw)).encode())[20:32]}",
        "specVersion": "1.6",
        "version": 1,
    }
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def expected() -> dict[str, bytes]:
    return {f"{workspace}.cdx.json": build_sbom(workspace, lock) for workspace, lock in WORKSPACES}


def write_all(output: pathlib.Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    observed = {path.name for path in output.iterdir() if path.is_file()}
    wanted = set(expected())
    if observed - wanted:
        raise SbomError(f"unexpected SBOM output members: {sorted(observed - wanted)}")
    for name, raw in expected().items():
        (output / name).write_bytes(raw)


def check_all(output: pathlib.Path) -> None:
    generated = expected()
    observed = {path.name for path in output.iterdir() if path.is_file()} if output.is_dir() else set()
    if observed != set(generated):
        raise SbomError("SBOM output file closure differs")
    for name, raw in generated.items():
        if (output / name).read_bytes() != raw:
            raise SbomError(f"SBOM differs: {name}")


def self_test() -> None:
    first = expected()
    second = expected()
    if first != second or len(first) != 5:
        raise AssertionError("SBOM generation is not deterministic")
    for raw in first.values():
        parsed = json.loads(raw)
        if parsed["bomFormat"] != "CycloneDX" or parsed["specVersion"] != "1.6":
            raise AssertionError("SBOM identity differs")


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--generate", action="store_true")
    action.add_argument("--check", action="store_true")
    action.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("release SBOM self-test passed")
            return 0
        if args.output is None:
            parser.error("--generate/--check requires --output")
        if args.generate:
            write_all(args.output)
            print(f"generated five deterministic CycloneDX 1.6 SBOMs in {args.output}")
        else:
            check_all(args.output)
            print(f"verified five deterministic CycloneDX 1.6 SBOMs in {args.output}")
        return 0
    except (OSError, UnicodeError, ValueError, SbomError) as error:
        print(f"release SBOM error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
