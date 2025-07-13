from grader import X64Grader, MaximumCountFilter

from unicorn.x86_const import *

import random


class Grader(X64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        Grader.filter(
            code,
            MaximumCountFilter(4)
        )

        uc = Grader.setup_unicorn()
        
        solved = True
        for _ in range(16):
            rbx = random.randint(0, 0xffffffffffffffff)
            uc.reg_write(UC_X86_REG_RBX, rbx)

            Grader.run_unicorn(code, uc)

            expected = int(f"{rbx:064b}"[::-1], 2)

            if uc.reg_read(UC_X86_REG_RAX) != expected:
                solved = False
                break

        return solved, [
            ("Inputs", f"rbx: 0x{rbx:016x}"),
            ("Registers", Grader.register_snapshot(uc))
        ]
