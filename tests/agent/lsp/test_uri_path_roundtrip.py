"""Regression: a server-echoed ``file://`` URI must map back to the caller's document path.

Node-based language servers (typescript-language-server, and every other server that
re-normalises through ``vscode-uri``) do not echo our URI back verbatim: the drive colon comes
back percent-encoded (``file:///c%3A/Users/...``) and the drive letter lower-cased.  ``uri_to_path``
used to look for the drive colon *before* ``unquote``, so both spellings missed the guard and it
returned the phantom path ``\\c:\\Users\\...``.  The client's document store is keyed by path, so
every diagnostic pushed under such a URI was filed in an entry no caller ever looked up and the
retrieval returned ``[]``: the server's errors surfaced as "no data", never as an error.

Windows-only: the mapping under test is a Windows drive path.
"""
from __future__ import annotations

import os

import pytest

from agent.lsp.client import LSPClient, file_uri, uri_to_path

pytestmark = pytest.mark.windows_only

_DIAG = {"range": {"start": {"line": 0, "character": 6}, "end": {"line": 0, "character": 7}},
         "severity": 1, "code": 2322, "source": "typescript",
         "message": "Type 'string' is not assignable to type 'number'."}


def test_server_echoed_uri_maps_to_caller_path(tmp_path):
    target = tmp_path / "Bad.ts"
    target.write_text("const n: number = 'x'\n", encoding="utf-8")
    caller_path = os.path.abspath(str(target))
    drive, rest = caller_path[0], caller_path[2:].replace(os.sep, "/")

    for uri in (
        f"file:///{drive.lower()}%3A{rest}",  # vscode-uri: colon encoded, drive letter lowered
        f"file:///{drive.upper()}:{rest}",    # the spelling file_uri() sends, echoed verbatim
        f"file:///{drive.upper()}%3A{rest}",  # encoded colon, drive letter preserved
    ):
        assert uri_to_path(uri) == caller_path, uri

    assert uri_to_path(file_uri(caller_path)) == caller_path

    # The symptom was a key mismatch, not a parsing failure: drive the real store path with the
    # URI a Node server pushes back and read it the way the manager does.
    client = LSPClient(server_id="typescript", workspace_root=str(tmp_path), command=["unused"])
    client._handle_publish_diagnostics(
        {"uri": f"file:///{drive.lower()}%3A{rest}", "diagnostics": [_DIAG]}
    )
    assert [d.get("code") for d in client.diagnostics_for(caller_path)] == [2322]