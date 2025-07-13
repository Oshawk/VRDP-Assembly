from grader import X64Grader, MaximumCountFilter

from unicorn.x86_const import *

import random


class Grader(X64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        Grader.filter(
            code,
            MaximumCountFilter(2)
        )

        solved = True
        for _ in range(16):
            uc = Grader.setup_unicorn()

            rax = random.randint(0, 1000000)
            rbx = random.randint(0, 1000000)

            uc.reg_write(UC_X86_REG_RAX, rax)
            uc.reg_write(UC_X86_REG_RBX, rbx)

            Grader.run_unicorn(code, uc)

            if uc.reg_read(UC_X86_REG_RAX) != max(rax, rbx):
                solved = False
                break

        return solved, [
            ("Inputs", f"rax: 0x{rax:016x}\nrbx: 0x{rbx:016x}"),
            ("Registers", Grader.register_snapshot(uc))
        ]
