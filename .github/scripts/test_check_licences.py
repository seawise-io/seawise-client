import importlib.util
import io
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


if __name__ == "__main__":
    unittest.main()
