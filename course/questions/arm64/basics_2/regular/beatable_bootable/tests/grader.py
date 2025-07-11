from grader import ARM64Grader, AllowOpcodesFilter, MaximumCountFilter

from unicorn.arm64_const import *


class Grader(ARM64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        Grader.filter(
            code,
            AllowOpcodesFilter("lsl", "ror"),
            MaximumCountFilter(3)
        )

        uc = Grader.setup_unicorn()
        
        uc.reg_write(UC_ARM64_REG_X0, 0xbea7ab1e)
        
        Grader.run_unicorn(code, uc)
        
        solved = uc.reg_read(UC_ARM64_REG_X0) == 0xb007ab1e

        return solved, [
            ("Registers", Grader.register_snapshot(uc))
        ]
