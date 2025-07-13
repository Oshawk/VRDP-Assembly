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

            m_20000 = random.randint(0, 1000000)
            m_20008 = random.randint(0, 1000000)

            uc.mem_write(0x20000, m_20000.to_bytes(8, "little"))
            uc.mem_write(0x20008, m_20008.to_bytes(8, "little"))

            Grader.run_unicorn(code, uc)

            expected = m_20000 + m_20008

            if uc.mem_read(0x20000, 8) != expected.to_bytes(8, "little"):
                solved = False
                break

        return solved, [
            ("Inputs", f"[0x20000]: 0x{m_20000:016x}\n[0x20008]: 0x{m_20008:016x}"),
            ("Registers", Grader.register_snapshot(uc))
        ]
