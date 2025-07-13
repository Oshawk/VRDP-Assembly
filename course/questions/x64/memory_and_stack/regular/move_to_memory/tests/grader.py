from grader import X64Grader, MaximumCountFilter

from unicorn.x86_const import *


class Grader(X64Grader):
    @staticmethod
    def grade(answer: str) -> tuple[bool, list[tuple[str, str]]]:
        code = Grader.assemble(answer)

        Grader.filter(
            code,
            MaximumCountFilter(1)
        )

        uc = Grader.setup_unicorn()
        
        Grader.run_unicorn(code, uc)
        
        solved = uc.mem_read(0x20000, 16) == bytes.fromhex("de ad be ef 00 00 00 00 00 00 00 00 00 00 00 00")

        return solved, [
            ("Registers", Grader.register_snapshot(uc)),
            ("Memory", Grader.memory_snapshot(uc, 0x20000, 0x20010))
        ]
