from grader import X64Grader, MaximumCountFilter

from unicorn.x86_const import *

import random


class Grader(X64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        Grader.filter(
            code,
            MaximumCountFilter(1)
        )

        solved = True

        for _ in range(16):
            uc = Grader.setup_unicorn()

            rbx = random.randint(0, 1000000)
            rcx = random.randint(0, 1000000)

            uc.reg_write(UC_X86_REG_RBX, rbx)
            uc.reg_write(UC_X86_REG_RCX, rcx)

            Grader.run_unicorn(code, uc)

            expected = 4 * rbx + rcx + 7

            if uc.reg_read(UC_X86_REG_RAX) != expected:
                solved = False
                break

        return solved, [
            ("Inputs", f"rbx: 0x{rbx:016x}\nrcx: 0x{rcx:016x}"),
            ("Registers", Grader.register_snapshot(uc))
        ]
