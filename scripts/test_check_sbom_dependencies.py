import json
from pathlib import Path

from scripts.check_sbom_dependencies import (
    check,
    direct_dependencies,
    locked_versions,
    main,
    sbom_versions,
)

REQUIREMENTS_IN = """\
# Direct runtime dependencies.
fastapi
uvicorn
"""

# The shape pip-compile writes: a pin, its hashes, and where it came from.
REQUIREMENTS_TXT = """\
click==8.5.0 \\
    --hash=sha256:255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360
    # via uvicorn
fastapi==0.143.0 \\
    --hash=sha256:1acffe48206a80917cf7dac21992b5c44b25384e8902bf745c1fd9dabcf6c51f
    # via -r requirements.in
uvicorn==0.54.0 \\
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000
    # via -r requirements.in
"""


def package(purl: str | None) -> dict:
    """One package of an SPDX document, named by its purl as Trivy names it."""
    if purl is None:
        return {"name": "debian", "versionInfo": "13.7"}
    reference = {
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": purl,
    }
    return {"name": purl, "externalRefs": [reference]}


def sbom(*purls: str | None) -> dict:
    return {"spdxVersion": "SPDX-2.3", "packages": [package(purl) for purl in purls]}


COMPLETE = sbom(
    None,
    "pkg:deb/debian/libc6@2.41-12?arch=amd64&distro=debian-13.7",
    "pkg:pypi/click@8.5.0",
    "pkg:pypi/fastapi@0.143.0",
    "pkg:pypi/uvicorn@0.54.0",
)


# Reading the three files


def test_direct_dependencies_are_the_names_in_requirements_in():
    assert direct_dependencies(REQUIREMENTS_IN) == ["fastapi", "uvicorn"]


def test_options_comments_extras_and_version_ranges_are_not_part_of_a_name():
    text = "-c requirements.txt\nhttpx2  # the test client\nuvicorn[standard]>=0.50\n\n"

    assert direct_dependencies(text) == ["httpx2", "uvicorn"]


def test_names_are_compared_the_way_python_compares_them():
    assert direct_dependencies("Typing_Extensions\n") == ["typing-extensions"]
    assert locked_versions("typing.extensions==4.16.0\n") == {"typing-extensions": "4.16.0"}
    assert sbom_versions(sbom("pkg:pypi/Typing_Extensions@4.16.0")) == {
        "typing-extensions": {"4.16.0"}
    }


def test_locked_versions_are_the_pins_and_not_the_hashes_or_comments():
    assert locked_versions(REQUIREMENTS_TXT) == {
        "click": "8.5.0",
        "fastapi": "0.143.0",
        "uvicorn": "0.54.0",
    }


def test_only_python_packages_are_read_from_the_sbom():
    assert sbom_versions(COMPLETE) == {
        "click": {"8.5.0"},
        "fastapi": {"0.143.0"},
        "uvicorn": {"0.54.0"},
    }


def test_a_purl_may_carry_qualifiers():
    assert sbom_versions(sbom("pkg:pypi/fastapi@0.143.0?extension=whl")) == {"fastapi": {"0.143.0"}}


def test_an_sbom_without_packages_lists_nothing():
    assert sbom_versions({}) == {}
    assert sbom_versions({"packages": None}) == {}


# The check


def test_an_sbom_that_lists_each_direct_dependency_as_locked_passes():
    found, problems = check(REQUIREMENTS_IN, REQUIREMENTS_TXT, COMPLETE)

    assert found == ["fastapi 0.143.0", "uvicorn 0.54.0"]
    assert problems == []


def test_a_dependency_missing_from_the_sbom_fails():
    incomplete = sbom("pkg:pypi/fastapi@0.143.0")

    found, problems = check(REQUIREMENTS_IN, REQUIREMENTS_TXT, incomplete)

    assert found == ["fastapi 0.143.0"]
    assert problems == ["uvicorn 0.54.0 is not in the SBOM"]


def test_a_dependency_at_another_version_fails_and_says_which():
    stale = sbom("pkg:pypi/fastapi@0.142.0", "pkg:pypi/uvicorn@0.54.0")

    _, problems = check(REQUIREMENTS_IN, REQUIREMENTS_TXT, stale)

    assert problems == ["fastapi is locked at 0.143.0, but the SBOM lists 0.142.0"]


def test_a_longer_version_that_starts_the_same_is_another_version():
    close = sbom("pkg:pypi/fastapi@0.143.0.post1", "pkg:pypi/uvicorn@0.54.0")

    _, problems = check(REQUIREMENTS_IN, REQUIREMENTS_TXT, close)

    assert problems == ["fastapi is locked at 0.143.0, but the SBOM lists 0.143.0.post1"]


def test_a_package_of_the_same_name_from_another_ecosystem_does_not_count():
    debian_only = sbom("pkg:deb/debian/fastapi@0.143.0", "pkg:pypi/uvicorn@0.54.0")

    _, problems = check(REQUIREMENTS_IN, REQUIREMENTS_TXT, debian_only)

    assert problems == ["fastapi 0.143.0 is not in the SBOM"]


def test_an_sbom_without_python_packages_fails_for_every_dependency():
    _, problems = check(REQUIREMENTS_IN, REQUIREMENTS_TXT, sbom(None))

    assert len(problems) == 2


def test_a_direct_dependency_that_is_not_locked_fails():
    _, problems = check("fastapi\nrequests\n", REQUIREMENTS_TXT, COMPLETE)

    assert problems == ["requests is not pinned in the lock"]


def test_a_transitive_dependency_missing_from_the_sbom_is_not_asked_about():
    without_click = sbom("pkg:pypi/fastapi@0.143.0", "pkg:pypi/uvicorn@0.54.0")

    assert check(REQUIREMENTS_IN, REQUIREMENTS_TXT, without_click)[1] == []


def test_a_requirements_in_without_dependencies_does_not_pass_for_want_of_them():
    found, problems = check("# nothing here\n", REQUIREMENTS_TXT, COMPLETE)

    assert found == []
    assert len(problems) == 1
    assert "names no dependency" in problems[0]


# The command line


def write(tmp_path, document) -> list[str]:
    """Write the three files and return their paths in command-line order."""
    paths = [tmp_path / "requirements.in", tmp_path / "requirements.txt", tmp_path / "sbom.json"]
    texts = [REQUIREMENTS_IN, REQUIREMENTS_TXT, document]
    for path, text in zip(paths, texts, strict=True):
        path.write_text(text, encoding="utf-8")
    return [str(path) for path in paths]


def test_the_command_line_passes_and_prints_what_it_found(tmp_path, capsys):
    assert main(write(tmp_path, json.dumps(COMPLETE))) == 0

    captured = capsys.readouterr()
    assert captured.out == "fastapi 0.143.0\nuvicorn 0.54.0\n"
    assert captured.err == ""


def test_the_command_line_fails_and_names_the_missing_dependency(tmp_path, capsys):
    assert main(write(tmp_path, json.dumps(sbom("pkg:pypi/fastapi@0.143.0")))) == 1

    captured = capsys.readouterr()
    assert captured.out == "fastapi 0.143.0\n"  # what was found is still printed
    assert "uvicorn 0.54.0 is not in the SBOM" in captured.err


def test_the_command_line_fails_on_a_file_that_is_not_json(tmp_path, capsys):
    assert main(write(tmp_path, "")) == 1
    assert "cannot be read as JSON" in capsys.readouterr().err


def test_the_command_line_fails_on_json_that_is_not_a_document(tmp_path, capsys):
    assert main(write(tmp_path, "null")) == 1
    assert "not an SPDX document" in capsys.readouterr().err


def test_the_files_of_this_repository_are_in_the_shape_the_check_reads():
    app = Path(__file__).resolve().parent.parent / "app"

    names = direct_dependencies((app / "requirements.in").read_text(encoding="utf-8"))
    locked = locked_versions((app / "requirements.txt").read_text(encoding="utf-8"))

    assert names == ["fastapi", "uvicorn"]
    assert set(names) <= set(locked)
