import click

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from c_table import c_instructions

def int_to_16bit_binary(number):
    return format(number & 0xFFFF, '016b')


@dataclass
class Hacked:
    input_file: Path
    output_file: Path
    mem_addr: int = 16
    asm_cmds: List[str] = field(default_factory=list)
    hack_cmds: List[str] = field(default_factory=list)
    symbol_table: dict = field(default_factory=dict)

    def __post_init__(self):
        with open(self.input_file, 'r') as file:
            self.asm_cmds = [line.strip() for line in file if line.strip() and not line.strip().startswith("/")]
        registers: dict = {f"R{addr}": addr for addr in range(16)}
        special_vars: dict = {
            "SCREEN": 16384,
            "KBD": 24576,
            "SP": 0,
            "LCL": 1,
            "ARG": 2,
            "THIS": 3,
            "THAT": 4,
        }
        self.symbol_table = registers | special_vars
        self.get_labels()
        self.get_vars()

    def get_labels(self):
        count: int = 0
        while count < len(self.asm_cmds):
            if self.asm_cmds[count].startswith("(") and self.asm_cmds[count].endswith(")"):
                self.symbol_table[self.asm_cmds[count][1:-1]] = count
                self.asm_cmds.pop(count)
            else:
                count += 1

    def get_vars(self):
        for index, command in enumerate(self.asm_cmds):
            if command.startswith("@") and command[1:] not in self.symbol_table and not command[1:].isdigit():
                self.symbol_table[command[1:]] = self.mem_addr
                self.mem_addr += 1

    def parse_commands(self):
        for command in self.asm_cmds:
            if command.startswith("@"):
                cmd = self.parse_a_command(addr=command[1:])
            else:
                cmd = self.parse_c_command(cmd_str=command)
            self.hack_cmds.append(cmd)

    def parse_a_command(self, addr: str) -> bin:
        cmd = self.symbol_table.get(addr, addr)
        return int_to_16bit_binary(int(cmd))

    def parse_c_command(self, cmd_str: str) -> str:
        cmd = cmd_str.split(" /")[0]
        command = cmd.split(";")
        jump = self.get_jump(cmd_str=command[1]) if ";" in cmd else "000"
        dest, comp = self.get_comp_and_dest(cmd_str=command[0])
        return f"111{comp}{dest}{jump}"

    @staticmethod
    def get_comp_and_dest(cmd_str: str) -> tuple:
        cmd = cmd_str.split("=")
        dest = c_instructions.get("dest").get(cmd[0]) if len(cmd) == 2 else "000"
        comp_part = cmd[1] if len(cmd) == 2 else cmd[0]
        comp = c_instructions.get("comp").get(comp_part, "0101010")
        return dest, comp

    @staticmethod
    def get_jump(cmd_str: str) -> str:
        jump = c_instructions.get("jump").get(cmd_str)
        return jump

    def write_hack(self):
        with open(self.output_file, "w+") as hack:
            for line in self.hack_cmds:
                hack.write(line + "\n")

@click.command()
@click.argument("filename")
def main(filename: str):
    asm_file = Path(filename)
    if not asm_file.exists():
        raise FileNotFoundError(f"{asm_file.as_posix()} not found")

    if asm_file.suffix != ".asm":
        raise ValueError(f"{asm_file.as_posix()} is not a .asm file")

    hack_file = Path("rendered").joinpath(asm_file.name).with_suffix(".hack")
    asm_parser = Hacked(input_file=asm_file, output_file=hack_file)
    asm_parser.parse_commands()
    asm_parser.write_hack()
    for index, cmd in enumerate(asm_parser.asm_cmds):
        print(cmd)

if __name__ == "__main__":
    main()
