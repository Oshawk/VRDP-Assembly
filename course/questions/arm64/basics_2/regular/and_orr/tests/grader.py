from grader import ARM64Grader, AllowOpcodesFilter, AllowOperandTypesFilter, MaximumCountFilter

from capstone import CS_OP_REG
from unicorn.arm64_const import *


class Grader(ARM64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        Grader.filter(
            code,
            AllowOpcodesFilter("and", "orr"),
            AllowOperandTypesFilter(CS_OP_REG),
            MaximumCountFilter(2)
        )

        uc = Grader.setup_unicorn()
        
        uc.reg_write(UC_ARM64_REG_X0, 0xdeadbeef)
        uc.reg_write(UC_ARM64_REG_X1, 0xffff)
        uc.reg_write(UC_ARM64_REG_X2, 0xf00f)

        Grader.run_unicorn(code, uc)
        
        solved = uc.reg_read(UC_ARM64_REG_X3) == 0xfeef

        return solved, [
            ("Registers", Grader.register_snapshot(uc))
        ]
