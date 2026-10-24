import sys

if len(sys.argv) > 1 and sys.argv[1] == "hook" and len(sys.argv) <= 3:
    # Fast path for the hook: skip argparse and the rest of the CLI, which the agents never need.
    from .hook import main as hook_main

    raise SystemExit(hook_main(fail_open=True if "--fail-open" in sys.argv else None))

from .cli import main

raise SystemExit(main())
