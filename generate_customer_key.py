"""
PULSEAI — generate_customer_key.py

Generates a new API key for a pilot customer, and prints exactly what to
add to your .env file. Each customer gets their own key, so revoking one
later never affects the others.

Run:
    python generate_customer_key.py "Company Name"

Example:
    python generate_customer_key.py "Vanta"
    python generate_customer_key.py "Acme Inc"

After running it for each company you're onboarding, your PULSEAI_API_KEYS
line in .env should look like this (comma-separated, no spaces around the
commas needed, but fine if there are):

    PULSEAI_API_KEYS=Vanta:8f3a91c2e6b7d401...,Acme Inc:2b7e4f1502a9b3d8...

Restart the server after editing .env for the change to take effect.
"""

import sys
import secrets


def main():
    if len(sys.argv) < 2:
        print("\nUsage: python generate_customer_key.py \"Company Name\"\n")
        sys.exit(1)

    company_name = " ".join(sys.argv[1:])
    new_key = secrets.token_hex(24)

    print(f"\nNew key generated for: {company_name}\n")
    print(f"Send this key to them privately (e.g. Slack DM, not email):")
    print(f"  {new_key}\n")
    print("Add this to your .env file's PULSEAI_API_KEYS line:")
    print(f"  {company_name}:{new_key}\n")
    print("If PULSEAI_API_KEYS doesn't exist yet in your .env, add a new line:")
    print(f"  PULSEAI_API_KEYS={company_name}:{new_key}\n")
    print("If it already has other companies on it, add a comma then this pair:")
    print(f"  ,{company_name}:{new_key}\n")
    print("Restart the server after saving for this to take effect.\n")


if __name__ == "__main__":
    main()
