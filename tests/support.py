import subprocess


def run_command(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=20, **kwargs)
    if result.returncode:
        raise AssertionError(f"{args[0]} failed: {result.stderr}")
    return result.stdout
