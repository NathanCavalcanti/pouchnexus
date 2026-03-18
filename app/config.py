# app/config.py
from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

from dotenv import load_dotenv
from groq import Groq, GroqError, RateLimitError, APIStatusError
from app.logger import debug_log

# Load environment variables from .env in project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
ENV_PATH = os.path.join(PROJECT_ROOT, ".env")
load_dotenv(ENV_PATH)

# ===== GROQ Configuration =====
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise RuntimeError(
        "GROQ_API_KEY is not configured. "
        "Add it to your environment or to the .env file in the project root."
    )

# Default model for general agents (IOC, MITRE, CVE)
GROQ_MODEL_DEFAULT = os.getenv("GROQ_MODEL_DEFAULT")

# Analysis model for complex agents (Investigation, Report)
GROQ_MODEL_ANALYSIS = os.getenv("GROQ_MODEL_ANALYSIS")

# Legacy support: GROQ_MODEL falls back to default
GROQ_MODEL = os.getenv("GROQ_MODEL", GROQ_MODEL_DEFAULT)

groq_client = Groq(api_key=GROQ_API_KEY)

# ===== GEMINI Configuration (Optional - Fallback only) =====
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL")

# Import Gemini SDK only if API key is configured
if GEMINI_API_KEY:
    try:
        import google.generativeai as genai

        genai.configure(api_key=GEMINI_API_KEY)
    except ImportError:
        print("[WARNING] google-generativeai not installed. Gemini fallback disabled.")
        GEMINI_API_KEY = None
else:
    print("[INFO] GEMINI_API_KEY not configured. Gemini fallback disabled.")

# ===== VirusTotal Configuration (Optional) =====
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
# Note: VirusTotal is optional. If not configured, hash analysis will be skipped.


def call_llm(
    messages: List[Dict[str, str]],
    provider: str = "groq",
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 2048,
) -> str:
    """
    Wraps LLM calls (Groq or Gemini) with automatic fallback and error handling.

    Args:
        messages: List of messages in format [{"role": "system|user|assistant", "content": "..."}]
        provider: "groq" or "gemini" (default: "groq")
        model: Specific model to use (if None, uses provider default)
        temperature: Generation temperature
        max_tokens: Max output tokens

    Returns:
        LLM response as string

    Raises:
        RuntimeError: If both Groq and Gemini fail
    """
    if provider == "groq":
        try:
            return _call_groq(messages, model or GROQ_MODEL, temperature, max_tokens)
        except RuntimeError as e:
            # Fallback to Gemini if Groq fails and Gemini is configured
            if GEMINI_API_KEY and "LLM_RATE_LIMIT" in str(e):
                print("[FALLBACK] Groq rate limit reached. Falling back to Gemini...")
                return _call_gemini(messages, GEMINI_MODEL, temperature, max_tokens)
            else:
                raise
    elif provider == "gemini":
        return _call_gemini(messages, model or GEMINI_MODEL, temperature, max_tokens)
    else:
        raise ValueError(f"Unsupported provider: {provider}. Use 'groq' or 'gemini'.")


def _call_groq(
    messages: List[Dict[str, str]],
    model: str,
    temperature: float,
    max_tokens: int,
) -> str:
    """Groq LLM call with error handling."""
    try:
        debug_log(f"=== GROQ API REQUEST ({model}) ===", messages)
        completion = groq_client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        content = completion.choices[0].message.content or ""
        debug_log(f"=== GROQ API RESPONSE ({model}) ===", content)
        return content
    except RateLimitError as e:
        raise RuntimeError(
            f"LLM_RATE_LIMIT: Groq model usage limit reached "
            f"('{model}'). Provider message: {e}"
        ) from e
    except APIStatusError as e:
        raise RuntimeError(
            f"LLM_API_ERROR: Groq API error for model '{model}': {e}"
        ) from e
    except GroqError as e:
        raise RuntimeError(f"LLM_ERROR: Error calling Groq model '{model}': {e}") from e
    except Exception as e:
        raise RuntimeError(
            f"LLM_UNKNOWN_ERROR: Unexpected error calling Groq model '{model}': {e}"
        ) from e


def _call_gemini(
    messages: List[Dict[str, str]],
    model: str,
    temperature: float,
    max_tokens: int,
) -> str:
    """
    Gemini LLM call with error handling.

    Note: Gemini does not support "system" role like OpenAI/Groq.
    We combine system + user into a single message.
    """
    try:
        # Combine messages (Gemini has no "system" role)
        combined_content = ""
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            if role == "system":
                combined_content = content + "\n\n"
            elif role == "user":
                combined_content += content
            # Ignore "assistant" for now (not used in our agents)

        # Create model and generate
        model_instance = genai.GenerativeModel(model)
        debug_log(f"=== GEMINI API REQUEST ({model}) ===", combined_content)

        response = model_instance.generate_content(
            combined_content,
            generation_config=genai.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            ),
        )
        debug_log(f"=== GEMINI API RESPONSE ({model}) ===", response.text)
        return response.text

    except Exception as e:
        # Gemini can raise different types of errors
        error_msg = str(e).lower()

        if "quota" in error_msg or "rate" in error_msg or "limit" in error_msg:
            raise RuntimeError(
                f"LLM_RATE_LIMIT: Gemini model usage limit reached "
                f"('{model}'). Provider message: {e}"
            ) from e
        elif "api" in error_msg or "status" in error_msg:
            raise RuntimeError(
                f"LLM_API_ERROR: Gemini API error for model '{model}': {e}"
            ) from e
        else:
            raise RuntimeError(
                f"LLM_ERROR: Error calling Gemini model '{model}': {e}"
            ) from e


def extract_json_block(text: str) -> str:
    """
    Extracts the first JSON block from text that may contain ```json ... ```.

    - If it finds a ```json ... ``` block, it uses that.
    - If not, it tries to find the first { ... } that looks like JSON.
    """
    # 1) Search for markdown block ```json ... ```
    code_block_pattern = re.compile(r"```json(.*?)```", re.DOTALL | re.IGNORECASE)
    match = code_block_pattern.search(text)
    if match:
        return match.group(1).strip()

    # 2) Fallback: try to grab from the first '{' to the last '}'.
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1].strip()

    # 3) If there's no way to extract JSON, return text as is
    # for the caller to decide what to do.
    return text.strip()
