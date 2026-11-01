"""Drive one pamtester authentication through a terminal.

Usage: converse SERVICE USER STEP...

A step "?TEXT" waits for TEXT in the output. A step "!TEXT" types TEXT and
Enter. A step "=PATH" waits until the file PATH exists. The script prints
the output and exits with the status of pamtester.
"""

import io
import os
import sys
import time

import pexpect


def main():
    service, user, *steps = sys.argv[1:]
    output = io.StringIO()
    # pamtester sets PAM_TTY only on request. The terminal is the pty that
    # pexpect gives to pamtester, so that pam_biometrics.so finish can read
    # trigger lines from it.
    command = 'exec pamtester -I "tty=$(tty)" "$0" "$1" authenticate'
    child = pexpect.spawn(
        "sh",
        ["-c", command, service, user],
        encoding="utf-8",
        timeout=60,
    )
    child.logfile_read = output
    step = "the end of the output"
    try:
        for step in steps:
            kind, text = step[0], step[1:]
            if kind == "?":
                child.expect_exact(text)
            elif kind == "!":
                child.sendline(text)
            elif kind == "=":
                while not os.path.exists(text):
                    time.sleep(0.2)
            else:
                sys.exit(f"unknown step: {step}")
        child.expect(pexpect.EOF)
    except pexpect.ExceptionPexpect as error:
        print(output.getvalue())
        print(f"converse: {type(error).__name__} at step {step!r}")
        sys.exit(2)
    child.close()
    print(output.getvalue())
    sys.exit(1 if child.exitstatus is None else child.exitstatus)


main()
