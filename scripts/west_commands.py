# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

from west.commands import WestCommand
from west import log
import subprocess
import os

class MergeCompileCommandsCommand(WestCommand):
    def __init__(self):
        super().__init__(
            "mcc",
            "Merge all compile_commands.json files into one",
            "Merge all compile_commands.json files into one."
        )

    def do_add_parser(self, parser_adder):
        return parser_adder.add_parser(self.name, help=self.help)

    def do_run(self, args, unknown_args):
        workspace_root, output_file = self.topdir, os.path.join(os.path.dirname(self.manifest.path), "compile_commands.json")

        json_files = subprocess.run(
            ["find", workspace_root, "-name", "compile_commands.json"], capture_output=True, text=True, check=True
        ).stdout.strip().split("\n")

        if json_files == ['']:
            return print("No compile_commands.json files found!")

        with open(output_file, "w") as f:
            subprocess.run(["jq", "-s", "map(.[]) | unique_by(.file)"] + json_files, stdout=f, check=True)

        print(f"Merged compile_commands.json created at: {output_file}")
