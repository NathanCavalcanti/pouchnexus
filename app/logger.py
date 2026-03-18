import os
import logging
from datetime import datetime
from dotenv import dotenv_values

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
ENV_PATH = os.path.join(PROJECT_ROOT, ".env")
env_vars = dotenv_values(ENV_PATH)

DEBUG_LOGGING_ENABLED = env_vars.get("DEBUG_LOGGING_ENABLED", "false").lower() == "true"

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
if DEBUG_LOGGING_ENABLED:
    os.makedirs(LOGS_DIR, exist_ok=True)

# Create a custom logger
logger = logging.getLogger("soc_multiagent")
logger.setLevel(logging.DEBUG if DEBUG_LOGGING_ENABLED else logging.INFO)

# Formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')

# Only setup file handler if debug is enabled
if DEBUG_LOGGING_ENABLED and not logger.handlers:
    # Daily log file
    log_file = os.path.join(LOGS_DIR, f"debug_{datetime.now().strftime('%Y%m%d')}.log")
    
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)

def debug_log(message: str, data: any = None):
    """
    Helper function to write detailed debug logs if enabled.
    """
    if not DEBUG_LOGGING_ENABLED:
        return
        
    # caller_frame = inspect.currentframe().f_back
    # Extract linenumber for context (can be added to log if needed)
    # _lineno = caller_frame.f_lineno
    
    log_msg = f"{message}"
    if data is not None:
        if isinstance(data, str):
            log_msg += f"\n{data}"
        else:
            import json
            try:
                log_msg += f"\n{json.dumps(data, indent=2, default=str)}"
            except Exception:
                log_msg += f"\n{str(data)}"
                
    # Modify record dynamically or just build string
    logger.debug(log_msg)

