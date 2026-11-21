
# Proxy Armour 
### Real-Time AI Data Loss Prevention Gateway

Proxy Armour is a real-time security gateway that protects sensitive information from being exposed when developers use external AI tools such as ChatGPT, Claude, and Gemini.

## Key Features

- **Real-Time Traffic Interception:** Monitors outgoing AI requests using mitmproxy.
- **Sensitive Data Detection:** Identifies passwords, API keys, email addresses, and personal information using Regex, Entropy Analysis, and Python AST.
- **Security Policies:** Supports Allow, Tokenize, and Block actions.
- **Secure Tokenization:** Replaces sensitive values with temporary placeholder tokens before sending requests to AI platforms.
- **Response Restoration:** Restores original values in AI responses, including streaming responses.
- **Real-Time Dashboard:** Monitors security events, request activity, and policies.
- **Privacy-Focused Logging:** Stores metadata without retaining original prompts or sensitive values.

## Technology Stack

- **Backend:** Python, FastAPI, Pydantic
- **Proxy:** mitmproxy
- **Frontend:** Next.js, React.js, TypeScript
- **Database:** PostgreSQL
- **Real-Time Updates:** Redis
- **Deployment:** Docker Compose
- **Testing:** Pytest

## How It Works

1. Intercepts outgoing requests to supported AI platforms.
2. Scans requests for sensitive information.
3. Applies Allow, Tokenize, or Block policies.
4. Replaces sensitive information with temporary tokens.
5. Sends the protected request to the AI platform.
6. Restores original values in the response and records security metadata.

## Project Results

- 549 automated tests passing.
- 94% code coverage.
- 100% correct restoration in tested cases.
- 91% secret detection F1 score.
- Approximately 20–40 ms additional processing time per request.

*Results measured on synthetic test data; latency varies by environment.*

<img width="1170" height="517" alt="image" src="https://github.com/user-attachments/assets/35d07570-4bd7-49af-9814-043c4649484a" />
<img width="1917" height="881" alt="image" src="https://github.com/user-attachments/assets/02b332ea-ef6c-4e5b-8bb8-597a54b64367" />
<img width="1917" height="865" alt="image" src="https://github.com/user-attachments/assets/2fe6f7bb-dee0-40fc-bab8-aac726ab31fc" />


