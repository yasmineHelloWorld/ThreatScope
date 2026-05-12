import logging
import json
from typing import Optional

logger = logging.getLogger(__name__)

class GroqClient:
   
    def __init__(self, config: dict = None):
        config = config or {}
        self.api_key = config.get("api_key", "")
        self.model = config.get("model", "llama-3.1-8b-instant")
        self.max_tokens = config.get("max_tokens", 512)
        self.temperature = config.get("temperature", 0.1)

        # Detect if we are in mock mode
        self.is_mock = not self.api_key or self.api_key == "your-groq-api-key-here"

        if self.is_mock:
            logger.warning("Groq API key missing/placeholder. Running in MOCK mode.")
            self.client = None
        else:
            try:
                from groq import Groq
                self.client = Groq(api_key=self.api_key)
                logger.info("GroqClient initialized with model=%s", self.model)
            except Exception as e:
                logger.error("Failed to initialize Groq: %s. Falling back to MOCK.", e)
                self.is_mock = True
                self.client = None

    def get_completion(self, system_prompt: str, user_prompt: str) -> Optional[str]:
       
        if self.is_mock or not self.client:
            return None

        try:
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"},
            )
            return chat_completion.choices[0].message.content
        except Exception as e:
            logger.error("Groq API call failed: %s", e)
            return None
