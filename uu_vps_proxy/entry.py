import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from uu_vps_proxy.manager import main

raise SystemExit(main())
