import importlib.util
import io
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("lic", pathlib.Path(__file__).parent / "check-licences.py")
lic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lic)

TEXTS = {
    "MIT": "Permission is hereby granted, free of charge, to any person obtaining a copy",
    "Apache-2.0": "Apache License\n Version 2.0, January 2004",
    "BSD-3-Clause": "Redistribution and use in source and binary forms, with or without\nmodification... Neither the name of Google Inc.",
    "BSD-2-Clause": "Redistribution and use in source and binary forms, with or without modification",
    "AGPL-3.0": "GNU AFFERO GENERAL PUBLIC LICENSE Version 3",
    "LGPL": "GNU LESSER GENERAL PUBLIC LICENSE Version 3, 29 June 2007 ... GNU General Public License",
    # MPL 2.0 names the GPL family as secondary licences.
    "MPL-2.0": "Mozilla Public License, version 2.0 ... 1.12. \"Secondary License\" means either the GNU General "
               "Public License, Version 2.0, the GNU Lesser General Public License, Version 2.1, the GNU Affero "
               "General Public License, Version 3.0, or any later versions of those licenses.",
}
POLICY = {"allowed": ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause"],
          "decision": [{"module": "example.com/lgpl", "license": "LGPL", "reason": "r"}]}


class LicenceTest(unittest.TestCase):
    def test_classify(self):
        for spdx, text in TEXTS.items():
            self.assertEqual(lic.classify(text), spdx)

    def mod(self, tmp, path, text, name="LICENSE"):
        d = pathlib.Path(tmp) / path.replace("/", "_")
        d.mkdir()
        if text is not None:
            (d / name).write_text(text)
        return {"Path": path, "Version": "v1.0.0", "Dir": str(d)}

    def test_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            mods = [
                {"Path": "github.com/seawise/client", "Main": True},
                self.mod(tmp, "example.com/mit", TEXTS["MIT"], "LICENSE.txt"),
                self.mod(tmp, "example.com/lgpl", TEXTS["LGPL"]),
                self.mod(tmp, "example.com/agpl", TEXTS["AGPL-3.0"], "COPYING"),
                self.mod(tmp, "example.com/none", None),
            ]
            errors = lic.check(POLICY, mods)
        self.assertEqual(len(errors), 2)
        self.assertIn("example.com/agpl", errors[0])
        self.assertIn("unknown", errors[1])

    def test_modules_stream(self):
        stream = io.StringIO('{"Path": "a", "Main": true}\n{\n "Path": "b"\n}\n')
        self.assertEqual([m["Path"] for m in lic.modules(stream)], ["a", "b"])

    def test_npm_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name, text in (("axe-core", TEXTS["MPL-2.0"]), ("@scope/gpl", TEXTS["AGPL-3.0"])):
                d = root / "node_modules" / name
                d.mkdir(parents=True)
                (d / "LICENSE").write_text(text)
            lock = root / "package-lock.json"
            lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
                "": {"name": "tool"},
                "node_modules/axe-core": {"version": "4.13.0", "license": "MPL-2.0"},
                "node_modules/@scope/gpl": {"version": "1.0.0", "license": "MIT"},
                "node_modules/missing": {"version": "1.0.0"},
            }}))
            mods = list(lic.npm_modules(lock))
            self.assertEqual([m["Path"] for m in mods], ["axe-core", "@scope/gpl", "missing"])
            errors = lic.check({"allowed": ["MPL-2.0", "MIT"]}, mods)
        # The licence file decides, not the metadata the package claims.
        self.assertEqual(len(errors), 2)
        self.assertIn("@scope/gpl@1.0.0: licence AGPL-3.0", errors[0])
        self.assertIn("missing", errors[1])


if __name__ == "__main__":
    unittest.main()
