from grader import X64Grader, AllowOpcodesFilter, MaximumCountFilter

from unicorn.x86_const import *

import random


class Grader(X64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        Grader.filter(
            code,
            AllowOpcodesFilter("add", "sub"),
            MaximumCountFilter(2),
        )

        solved = True
        for _ in range(16):
            uc = Grader.setup_unicorn()

            rbx = random.randint(-1000000, 1000000)
            rbx_ = int.from_bytes(rbx.to_bytes(8, "little", signed=True), "little", signed=False)

            uc.reg_write(UC_X86_REG_RBX, rbx_)

            Grader.run_unicorn(code, uc)

            expected = int.from_bytes((-(rbx + 1000)).to_bytes(8, "little", signed=True), "little", signed=False)

            if uc.reg_read(UC_X86_REG_RAX) != expected:
                solved = False
                break
        
        return solved, [
            ("Inputs", f"rbx: 0x{rbx_:016x}"),
            ("Registers", Grader.register_snapshot(uc))
        ]
