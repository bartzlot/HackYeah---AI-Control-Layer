import os

import uvicorn

from .app import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host=os.environ.get("AICL_CLOUDSIM_HOST", "0.0.0.0"),
                port=int(os.environ.get("AICL_CLOUDSIM_PORT", "18200")))
