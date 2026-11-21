"""python -m mock_llm  -> serves the mock LLM on demo.upstream_host:upstream_port."""
import uvicorn

from armour_config import settings
from mock_llm.app import app

uvicorn.run(app, host=settings.demo.upstream_host, port=settings.demo.upstream_port)
