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
        
        solved = uc.reg_read(UC_X86_REG_RAX) == 0xf00dbeefdeadc0de

        return solved, [
            ("Registers", Grader.register_snapshot(uc))
        ]
