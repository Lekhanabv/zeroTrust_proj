
import os
from dotenv import load_dotenv
from groq import Groq

# Load settings from the local .env file
load_dotenv()

api_key = os.getenv("GROQ_API_KEY")
model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

if not api_key:
    print("ERROR: GROQ_API_KEY is missing from .env")
else:
    try:
        client = Groq(api_key=api_key)

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": "Reply with exactly: Groq connection successful"
                }
            ],
            max_tokens=30,
        )

        print("SUCCESS:", response.choices[0].message.content)

    except Exception as error:
        print("Connection failed:", type(error).__name__)
        print("Check your API key, model name, and account limits.")
