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
            
            rdx = random.randint(0, 1000000)
            r10 = random.randint(0, 1000000)

            uc.reg_write(UC_X86_REG_RDX, rdx)
            uc.reg_write(UC_X86_REG_R10, r10)

            Grader.run_unicorn(code, uc)

            if uc.reg_read(UC_X86_REG_R9) != rdx * r10:
                solved = False
                break

        return solved, [
            ("Inputs", f"rdx: 0x{rdx:016x}\nr10: 0x{r10:016x}"),
            ("Registers", Grader.register_snapshot(uc))
        ]
