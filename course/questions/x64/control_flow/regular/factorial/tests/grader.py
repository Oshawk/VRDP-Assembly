from grader import X64Grader

from unicorn.x86_const import *

import random


class Grader(X64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        solved = True
        for _ in range(16):
            uc = Grader.setup_unicorn()

            rbx = random.randint(1, 20)

            uc.reg_write(UC_X86_REG_RBX, rbx)

            Grader.run_unicorn(code, uc)

            expected = 1
            for i in range(1, rbx + 1):
                expected *= i

            if uc.reg_read(UC_X86_REG_RAX) != expected:
                solved = False
                break

        return solved, [
            ("Inputs", f"rbx: 0x{rbx:016x}"),
            ("Registers", Grader.register_snapshot(uc))
        ]
