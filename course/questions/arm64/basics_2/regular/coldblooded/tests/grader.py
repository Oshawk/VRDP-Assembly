from grader import ARM64Grader, AllowOpcodesFilter

from capstone import CS_OP_REG
from unicorn.arm64_const import *


class Grader(ARM64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        Grader.filter(
            code,
            AllowOpcodesFilter("mov", "movk")
        )

        uc = Grader.setup_unicorn()
        
        Grader.run_unicorn(code, uc)
        
        solved = uc.reg_read(UC_ARM64_REG_X0) == 0xc01db100ded

        return solved, [
            ("Registers", Grader.register_snapshot(uc))
        ]
