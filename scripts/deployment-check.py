#!/usr/bin/env python3
import asyncio
import json
import os
import re
import subprocess
import base64
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from dotenv import load_dotenv
from azure.core.credentials import AccessToken
from azure.identity import DefaultAzureCredential
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.web.models import CsmPublishingProfileOptions
from rich.console import Console
import sys
import warnings

# Suppress cleanup noise from asyncio subprocess transport
warnings.filterwarnings(
    "ignore",
    category=RuntimeWarning,
    message="coroutine 'BaseSubprocessTransport.__del__'"
)

console = Console()
load_dotenv()

RESOURCE_GROUP = os.environ.get("RESOURCE_GROUP")
APP_NAME = os.environ.get("APP_NAME")
SLOT = os.environ.get("SLOT")
SUBSCRIPTION_ID = os.environ.get("SUBSCRIPTION_ID")
USE_CLI_AUTH = os.getenv("USE_CLI_AUTH", "").lower() == "true"

SSH_CONNECTION_RETRY_COUNT = 3
SSH_CONNECTION_DELAY_IN_SECONDS = 2
CONSISTENCY_CHECK_MAX_RETRIES = 3
CONSISTENCY_CHECK_DELAY_IN_SECONDS = 10

# --------------------------------------
# Auth Helpers
# --------------------------------------
def get_cli_token():
    """Return an AccessToken object from Azure CLI."""
    result = subprocess.run(
        ["az", "account", "get-access-token", "--resource", "https://management.azure.com/"],
        capture_output=True, text=True, check=True,
    )
    token_data = json.loads(result.stdout)
    expires_on = int(datetime.strptime(token_data["expiresOn"], "%Y-%m-%d %H:%M:%S.%f").timestamp())
    return AccessToken(token_data["accessToken"], expires_on)


class CLIManagedIdentityCredential:
    """Credential class that uses Azure CLI token retrieval."""
    def get_token(self, *scopes, **kwargs):
        return get_cli_token()


credential = CLIManagedIdentityCredential() if USE_CLI_AUTH else DefaultAzureCredential()

# --------------------------------------
# Azure + Kudu
# --------------------------------------
def get_instance_ids():
    """Fetch App Service instance identifiers and Kudu credentials."""
    console.print("[cyan]🔍 Getting instance IDs...[/cyan]")
    client = WebSiteManagementClient(credential=credential, subscription_id=SUBSCRIPTION_ID)
    options = CsmPublishingProfileOptions(format="WebDeploy")

    if SLOT and SLOT.lower() != "production":
        instances = client.web_apps.list_instance_identifiers_slot(RESOURCE_GROUP, APP_NAME, SLOT)
        publishing_profile = client.web_apps.list_publishing_profile_xml_with_secrets_slot(
            RESOURCE_GROUP, APP_NAME, SLOT, publishing_profile_options=options
        )
    else:
        instances = client.web_apps.list_instance_identifiers(RESOURCE_GROUP, APP_NAME)
        publishing_profile = client.web_apps.list_publishing_profile_xml_with_secrets(
            RESOURCE_GROUP, APP_NAME, publishing_profile_options=options
        )

    xml_data = b"".join(publishing_profile).decode("utf-8")
    root = ET.fromstring(xml_data)
    msdeploy = root.find(".//publishProfile[@publishMethod='MSDeploy']")
    user, password = msdeploy.attrib["userName"], msdeploy.attrib["userPWD"]
    instances_list = [instance.id.split("/")[-1] for instance in instances]
    auth_b64 = base64.b64encode(f"{user}:{password}".encode()).decode()
    console.print(f"[green]✅ Found instances:[/green] {instances_list}")
    return instances_list, auth_b64

# --------------------------------------
# SSH Helpers
# --------------------------------------
async def get_instance_connection_details(instance_id):
    """Open remote SSH tunnel to App Service instance."""
    args = [
        "az", "webapp", "create-remote-connection",
        "--subscription", SUBSCRIPTION_ID,
        "--resource-group", RESOURCE_GROUP,
        "--instance", instance_id,
        "--name", APP_NAME,
    ]
    if SLOT and SLOT.lower() != "production":
        args.extend(["--slot", SLOT])

    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )

    port = None
    password = None

    async for line in proc.stdout:
        decoded = line.decode().strip()
        if not port:
            m = re.search(r"Opening tunnel on port: (\d+)", decoded)
            if m:
                port = m.group(1)
        if not password:
            pm = re.search(r"Password\s*:?\s*(\S+)", decoded, re.IGNORECASE)
            if pm:
                password = pm.group(1)
        if port and password:
            break

    if not (port and password):
        await close_tunnel(proc)
        raise RuntimeError(f"Could not establish tunnel for instance {instance_id}")
    return port, password, proc


async def close_tunnel(proc):
    """Close az tunnel subprocess safely."""
    if proc.returncode is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=2)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()


async def ssh_command(port, password, command):
    """Execute command on App Service instance over SSH."""
    ssh_cmd = [
        "sshpass", "-p", password, "ssh", "root@127.0.0.1",
        "-m", "hmac-sha1", "-p", str(port),
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", command,
    ]
    proc = await asyncio.create_subprocess_exec(
        *ssh_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return stdout.decode().strip(), stderr.decode().strip()

# --------------------------------------
# File Operations
# --------------------------------------
async def list_all_wwwroot_files(port, password):
    """List all files under /home/site/wwwroot recursively."""
    cmd = "cd /home/site/wwwroot && find . -type f"
    out, _ = await ssh_command(port, password, cmd)
    files = [f.strip().lstrip("./") for f in out.splitlines() if f.strip()]
    console.print(f"[cyan]📂 Found {len(files)} files under wwwroot[/cyan]")
    return files


async def get_file_checksum(port, password, file):
    """Return MD5 checksum of a given file."""
    for attempt in range(SSH_CONNECTION_RETRY_COUNT):
        out, _ = await ssh_command(port, password, f"md5sum /home/site/wwwroot/{file}")
        m = re.search(r"\b([a-fA-F0-9]{32})\b", out)
        if m:
            return m.group(1)
        await asyncio.sleep(SSH_CONNECTION_DELAY_IN_SECONDS)
    raise RuntimeError(f"Failed to get checksum for {file}")

# --------------------------------------
# Core Logic
# --------------------------------------
async def check_file_versions(instance_ids, kudu_auth_base64):
    """Compute MD5 for every file in every instance."""
    files_checksum_dict = {}

    for instance_id in instance_ids:
        port, password, tunnel_proc = await get_instance_connection_details(instance_id)
        console.print(f"[cyan]🔗 Connected to instance:[/cyan] {instance_id} (port {port})")

        try:
            files_to_check = await list_all_wwwroot_files(port, password)
            console.print(f"[grey58]Computing checksums...[/grey58]")

            for file in files_to_check:
                checksum = await get_file_checksum(port, password, file)
                files_checksum_dict.setdefault(file, {}).setdefault(checksum, set()).add(instance_id)
        finally:
            await close_tunnel(tunnel_proc)

    console.print("[blue]📊 Final checksums summary:[/blue]")
    console.print(json.dumps({k: {ck: list(v) for ck, v in d.items()} for k, d in files_checksum_dict.items()}, indent=2))
    return files_checksum_dict


def validate_file_versions(files_checksum_dict):
    """Compare checksums across instances and detect inconsistencies."""
    consistent = True
    for file, checksums in files_checksum_dict.items():
        if len(checksums) != 1:
            consistent = False
            console.print(f"[red]❌ Inconsistent file:[/red] {file}")
            for checksum, instances in checksums.items():
                console.print(f"   {checksum} → {', '.join(instances)}")
    return consistent

# --------------------------------------
# Main
# --------------------------------------
async def main():
    instance_ids, kudu_auth_base64 = get_instance_ids()

    for attempt in range(CONSISTENCY_CHECK_MAX_RETRIES):
        console.rule(f"Attempt {attempt + 1}/{CONSISTENCY_CHECK_MAX_RETRIES}")
        files_checksum_dict = await check_file_versions(instance_ids, kudu_auth_base64)
        if validate_file_versions(files_checksum_dict):
            console.print(f"[bold green]\n✅ All {SLOT or 'production'} instances are consistent![/bold green]")
            return
        if attempt < CONSISTENCY_CHECK_MAX_RETRIES - 1:
            console.print(f"[yellow]Retrying in {CONSISTENCY_CHECK_DELAY_IN_SECONDS}s...[/yellow]")
            await asyncio.sleep(CONSISTENCY_CHECK_DELAY_IN_SECONDS)

    raise ValueError("❌ Deployment consistency check failed: inconsistent file versions")

# --------------------------------------
# Entrypoint
# --------------------------------------
if __name__ == "__main__":
    console.print("[bold blue]🚀 Starting full MD5 consistency check for all files under /home/site/wwwroot[/bold blue]")
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main())
        loop.close()
        console.print("[green]🎉 Consistency check completed successfully[/green]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ {e}[/red]")
        sys.exit(1)
