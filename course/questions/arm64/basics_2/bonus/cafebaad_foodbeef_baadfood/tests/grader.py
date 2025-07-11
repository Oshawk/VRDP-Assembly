from grader import ARM64Grader, MaximumCountFilter

from unicorn.arm64_const import *


class Grader(ARM64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        Grader.filter(
            code,
            MaximumCountFilter(1)
        )

        uc = Grader.setup_unicorn()
        
        uc.reg_write(UC_ARM64_REG_X1, 0xcafebaad)
        uc.reg_write(UC_ARM64_REG_X2, 0xf00dbeef)
        
        Grader.run_unicorn(code, uc)
        
        solved = uc.reg_read(UC_ARM64_REG_X0) == 0xbaadf00d

        return solved, [
            ("Registers", Grader.register_snapshot(uc))
        ]
