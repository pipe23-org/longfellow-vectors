#!/usr/bin/env python3
"""Check the prose in a tool's Python files.

    python check_prose.py <directory>...

Rules: a test module has no module docstring; a docstring is one line; a string
literal does not name a docs page; a help= string is one clause under 80
characters.
"""

import ast
import sys
from pathlib import Path

ONE_LINE_EXEMPT = {"generation/mdoc.py"}


def findings(path: Path) -> list[str]:
    source = path.read_text()
    tree = ast.parse(source)
    found = []
    rel = path.as_posix()
    exempt = any(rel.endswith(name) for name in ONE_LINE_EXEMPT)

    def docstring(node: ast.AST) -> ast.Constant | None:
        body = getattr(node, "body", None)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            if isinstance(body[0].value.value, str):
                return body[0].value
        return None

    module_doc = docstring(tree)
    if module_doc is not None and "/tests/" in rel:
        found.append(f"{rel}:{module_doc.lineno}: test module docstring")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = docstring(node)
            if doc is not None and not exempt and "\n" in doc.value.strip():
                found.append(f"{rel}:{doc.lineno}: docstring longer than one line")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if "docs/" in node.value:
                found.append(f"{rel}:{node.lineno}: string names a docs page")
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "help" and isinstance(keyword.value, ast.Constant):
                    text = keyword.value.value
                    if ";" in text or len(text) > 80:
                        found.append(f"{rel}:{keyword.value.lineno}: help is not one clause")
    return found


def main() -> None:
    found = []
    for directory in sys.argv[1:]:
        for path in sorted(Path(directory).rglob("*.py")):
            if ".venv" in path.parts:
                continue
            found += findings(path)
    for line in found:
        print(line)
    sys.exit(1 if found else 0)


if __name__ == "__main__":
    main()
