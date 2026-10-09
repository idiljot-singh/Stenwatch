"""Console-mode runner: the windowless Stenwatch.exe calls stenwatch-cli.exe <script.py> [args] to stream a script's output."""
import runpy, sys

sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
