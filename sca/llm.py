"""LLM backend via the OpenAI SDK. Default = local Ollama (no cost, nothing leaves the machine);
switch to OpenAI (본선) or an in-house model (e.g. 아이멤버) with env vars only:

    SCA_LLM_BASE_URL       default http://localhost:11434/v1   (OpenAI: https://api.openai.com/v1)
    SCA_LLM_MODEL          default gpt-oss:20b                  (alt: gemma4:12b, gpt-5.1, ...)
    SCA_LLM_API_KEY        default "ollama"                     (OpenAI: OPENAI_API_KEY)
    SCA_LLM_REASONING      default "low" for gpt-oss / o-series / gpt-5 (reasoning_effort; "" to omit)
    SCA_LLM_TEMPERATURE    default 0; never sent to OpenAI reasoning models (o1/o3/o4/gpt-5),
                           which reject a non-default temperature
    SCA_LLM_TRUSTED_HOSTS  comma list of in-house hosts (e.g. "llm.corp.example,10.0.0.5") treated
                           like a local backend: reviewer notes may be used as few-shot examples

Not verified against the real OpenAI API in this PoC (only local Ollama); request kwargs are
unit-tested per model name (tests/test_llm_and_ingest.py).
"""
from __future__ import annotations

import json
import os
from typing import TypeVar
from urllib.parse import urlparse

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

REASONING_PREFIXES = ("o1", "o3", "o4", "gpt-5")     # OpenAI reasoning models: no temperature
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass


def is_reasoning_model(model: str) -> bool:
    m = model.rsplit("/", 1)[-1].lower()
    return m.startswith(REASONING_PREFIXES) and not m.startswith("gpt-5-chat")


def request_kwargs(model: str, reasoning: str = "", temperature: float | None = 0.0) -> dict:
    """Extra chat.completions kwargs for `model`: reasoning_effort when set; temperature only for
    models that accept it (OpenAI reasoning models return 400 for temperature != 1)."""
    kw: dict = {}
    if reasoning:
        kw["reasoning_effort"] = reasoning
    if temperature is not None and not is_reasoning_model(model):
        kw["temperature"] = temperature
    return kw


def _hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _host_match(host: str, patterns: list[str]) -> bool:
    return any(host == p or host.endswith("." + p) for p in patterns if p)


class LLM:
    def __init__(self, base_url: str | None = None, model: str | None = None, api_key: str | None = None):
        from openai import OpenAI
        _load_dotenv()
        self.base_url = base_url or os.environ.get("SCA_LLM_BASE_URL", "http://localhost:11434/v1")
        self.model = model or os.environ.get("SCA_LLM_MODEL", "gpt-oss:20b")
        key = api_key or os.environ.get("SCA_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY") or "ollama"
        self.client = OpenAI(base_url=self.base_url, api_key=key, timeout=300)
        m = self.model.rsplit("/", 1)[-1].lower()
        default_eff = "low" if (m.startswith("gpt-oss") or is_reasoning_model(self.model)) else ""
        self.reasoning = os.environ.get("SCA_LLM_REASONING", default_eff)
        t = os.environ.get("SCA_LLM_TEMPERATURE", "0").strip()
        self.temperature = float(t) if t else None
        self.trusted_hosts = [h.strip().lower() for h in
                              os.environ.get("SCA_LLM_TRUSTED_HOSTS", "").split(",") if h.strip()]
        self.cache_only = False      # set when the backend is unreachable: serve caches, never call

    def _extra(self) -> dict:
        return request_kwargs(self.model, self.reasoning, self.temperature)

    @property
    def is_local(self) -> bool:
        """Loopback backend (Ollama on this machine)."""
        return _hostname(self.base_url) in LOOPBACK

    @property
    def is_trusted(self) -> bool:
        """Local or in-house (SCA_LLM_TRUSTED_HOSTS) backend → internal context such as reviewer
        notes may be included in prompts. Public OpenAI endpoints are never trusted."""
        return self.is_local or _host_match(_hostname(self.base_url), self.trusted_hosts)

    @property
    def name(self) -> str:
        return f"{self.model}@{'local' if self.is_local else self.base_url}"

    def structured(self, system: str, user: str, schema: type[T], retries: int = 2) -> T:
        """Chat completion constrained to `schema` (JSON Schema structured output), validated."""
        if self.cache_only:
            raise RuntimeError("LLM backend unreachable (cache-only mode)")
        js = schema.model_json_schema()
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        last_err = None
        for _ in range(retries + 1):
            resp = self.client.chat.completions.create(
                model=self.model, messages=messages, **self._extra(),
                response_format={"type": "json_schema",
                                 "json_schema": {"name": schema.__name__, "schema": js}},
            )
            text = resp.choices[0].message.content or ""
            try:
                return schema.model_validate(json.loads(text))
            except (json.JSONDecodeError, ValidationError) as e:
                last_err = e
                messages += [{"role": "assistant", "content": text},
                             {"role": "user", "content": f"Invalid JSON for the schema: {e}. Return only valid JSON."}]
        raise RuntimeError(f"LLM structured output failed: {last_err}")

    def text(self, system: str, user: str) -> str:
        if self.cache_only:
            raise RuntimeError("LLM backend unreachable (cache-only mode)")
        resp = self.client.chat.completions.create(
            model=self.model, **self._extra(),
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
        return resp.choices[0].message.content or ""


def trusted(llm) -> bool:
    """llm.is_trusted, falling back to is_local for test doubles."""
    return bool(getattr(llm, "is_trusted", getattr(llm, "is_local", False)))
