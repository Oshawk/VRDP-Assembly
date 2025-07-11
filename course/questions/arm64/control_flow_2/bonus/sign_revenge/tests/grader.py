from grader import ARM64Grader, MaximumCountFilter

from unicorn.arm64_const import *

import random


class Grader(ARM64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        test_code = Grader.assemble(answer)

        Grader.filter(
            test_code,
            MaximumCountFilter(4)
        )


        pre = """
        call sign
        b end
        """

        post = """
        movz x0, #0
        end:
        """

        code = Grader.assemble(pre + answer + post)

        solved = True
        for i in range(10):
            uc = Grader.setup_unicorn()
            
            x0 = random.randint(-100, 100)

            uc.reg_write(UC_ARM64_REG_X0, x0)
            
            Grader.run_unicorn(code, uc)

            expected = 0
            if x0 > 0:
                expected = 1
            if x0 < 0:
                expected = 0xffffffffffffffff
            
            if uc.reg_read(UC_ARM64_REG_X0) != expected:
                solved = False
                break

        return solved, [
            ("Inputs", f"x0: 0x{x0:016x}"),
            ("Registers", Grader.register_snapshot(uc))
        ]

