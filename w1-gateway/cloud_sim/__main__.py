"""python -m cloud_sim: serve the priced mock upstream. Binds 127.0.0.1 by default; containers set
AICL_CLOUDSIM_HOST=0.0.0.0 (the compose port mapping keeps it host-only)."""
import os

DEFAULT_HOST, DEFAULT_PORT = "127.0.0.1", 18200


def serve_args(env=None) -> dict:
    env = os.environ if env is None else env
    return {"host": env.get("AICL_CLOUDSIM_HOST") or DEFAULT_HOST,
            "port": int(env.get("AICL_CLOUDSIM_PORT") or DEFAULT_PORT)}


if __name__ == "__main__":
    import uvicorn

    from .app import create_app

    uvicorn.run(create_app(), **serve_args())
