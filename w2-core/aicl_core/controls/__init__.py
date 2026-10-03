"""Every control module registers itself on import (order = evaluation order)."""
from . import access  # noqa: F401  KILL-01, ACCESS-01
from . import dlp  # noqa: F401  DLP-01 secrets, DLP-02 PII, DLP-05 destination matrix
from . import injection  # noqa: F401  INJ-03 signature rules
from . import tools  # noqa: F401  TOOL-01 tool firewall
