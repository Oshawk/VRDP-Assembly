#!/bin/sh

cp /grade/tests/grader.py /grader/grader.py

cat /grade/student/answer.s

python3 -m grader.bootstrap
