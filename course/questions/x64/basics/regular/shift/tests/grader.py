from grader import X64Grader, MaximumCountFilter

from unicorn.x86_const import *

import random


class Grader(X64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        uc = Grader.setup_unicorn()
        
        solved = True
        for _ in range(16):
            uc = Grader.setup_unicorn()
            
            rcx = random.randint(0, 1000000)
            rdx = random.randint(0, 63)

            uc.reg_write(UC_X86_REG_RCX, rcx)
            uc.reg_write(UC_X86_REG_RDX, rdx)

            Grader.run_unicorn(code, uc)

            expected = (rcx << rdx) & 0xffffffffffffffff

            if uc.reg_read(UC_X86_REG_RAX) != expected:
                solved = False
                break

        return solved, [
            ("Inputs", f"rcx: 0x{rcx:016x}\nrdx: 0x{rdx:016x}"),
            ("Registers", Grader.register_snapshot(uc))
        ]
