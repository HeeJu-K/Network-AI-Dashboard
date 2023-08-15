import sys, select, time, os, subprocess, sys
from dotenv import load_dotenv

load_dotenv()

if "OPENAI_API_KEY" not in os.environ:
    print("You must set an OPENAI_API_KEY using the Secrets tool", file=sys.stderr)
else:
    print("CONVERSATION STARTED")
    import process

    process.runPrompt()
