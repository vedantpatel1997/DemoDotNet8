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
from rich.table import Table
from rich.panel import Panel
import sys

# --------------------------------------
# Setup
# --------------------------------------
console = Console()
load_dotenv()

RESOURCE_GROUP = os.environ.get("RESOURCE_GROUP")
APP_NAME = os.environ.get("APP_NAME")
SLOT = os.environ.get("SLOT")
SUBSCRIPTION_ID = os.environ.get("SUBSCRIPTION_ID")
FILES_TO_CHECK = os.environ.get("FILES_TO_CHECK")

if not SUBSCRIPTION_ID:
    try:
        SUBSCRIPTION_ID = subprocess.run(
            ["az", "account", "show", "--query", "id", "-o", "tsv"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        console.print("[red]❌ Could not determine subscription ID from Azure CLI.[/red]")
        raise

if not FILES_TO_CHECK:
    raise RuntimeError("FILES_TO_CHECK environment variable must be provided (comma separated list)")

FILES_TO_CHECK = [file.strip() for file in FILES_TO_CHECK.split(",") if file.strip()]
USE_CLI_AUTH = os.getenv("USE_CLI_AUTH", "").lower() == "true"

SSH_CONNECTION_RETRY_COUNT = 3
SSH_CONNECTION_DELAY_IN_SECONDS = 2
CONSISTENCY_CHECK_MAX_RETRIES = 5
CONSISTENCY_CHECK_DELAY_IN_SECONDS = 10


# --------------------------------------
# Helper Classes & Auth
# --------------------------------------
def get_cli_token():
    result = subprocess.run(
        ["az", "account", "get-access-token", "--resource", "https://management.azure.com/"],
        capture_output=True, text=True, check=True,
    )
    token_data = json.loads(result.stdout)
    expires_on = int(datetime.strptime(token_data["expiresOn"], "%Y-%m-%d %H:%M:%S.%f").timestamp())
    return AccessToken(token_data["accessToken"], expires_on)


class CLIManagedIdentityCredential:
    def get_token(self, *scopes, **kwargs):
        return get_cli_token()


credential = CLIManagedIdentityCredential() if USE_CLI_AUTH else DefaultAzureCredential()

# --------------------------------------
# Azure + Kudu
# --------------------------------------
def get_instance_ids():
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

    publishing_profile_xml = b"".join(publishing_profile).decode("utf-8")
    profile_root = ET.fromstring(publishing_profile_xml)
    msdeploy_profile = profile_root.find(".//publishProfile[@publishMethod='MSDeploy']")
    user = msdeploy_profile.attrib["userName"]
    password = msdeploy_profile.attrib["userPWD"]
    instances_list = [instance.id.split("/")[-1] for instance in instances]
    kudu_auth_base64 = base64.b64encode(f"{user}:{password}".encode()).decode()
    console.print(f"[green]✅ Found instances:[/green] {instances_list}")
    return instances_list, kudu_auth_base64


# --------------------------------------
# Remote Commands via SSH Tunnel
# --------------------------------------
async def get_instance_connection_details(instance_id):
    args = [
        "az", "webapp", "create-remote-connection",
        "--subscription", SUBSCRIPTION_ID,
        "--resource-group", RESOURCE_GROUP,
        "--instance", instance_id,
        "--name", APP_NAME,
    ]
    if SLOT and SLOT.lower() != "production":
        args.extend(["--slot", SLOT])

    proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)

    port = None
    password = None

    async for line in proc.stdout:
        decoded = line.decode().strip()
        console.print(f"[grey58]{decoded}[/grey58]")
        if not port:
            m = re.search(r"Opening tunnel on port: (\d+)", decoded)
            if m: port = m.group(1)
        if not password:
            pm = re.search(r"Password\s*:?\s*(\S+)", decoded, re.IGNORECASE)
            if pm: password = pm.group(1)
        if port and password:
            break

    if not (port and password):
        await close_tunnel(proc)
        raise RuntimeError(f"Could not establish tunnel for instance {instance_id}")
    return port, password, proc


async def close_tunnel(proc):
    if proc.returncode is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=2)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()


async def ssh_command(port, password, command):
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


async def get_file_checksum(port, password, file):
    for attempt in range(SSH_CONNECTION_RETRY_COUNT):
        out, err = await ssh_command(port, password, f"md5sum {file}")
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        console.print(f"[grey62]md5sum output: {lines}[/grey62]")
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and re.fullmatch(r"[a-fA-F0-9]{32}", parts[0]):
                return parts[0]
        await asyncio.sleep(SSH_CONNECTION_DELAY_IN_SECONDS)
    raise RuntimeError(f"Failed to get checksum for {file} after {SSH_CONNECTION_RETRY_COUNT} retries")


async def get_instance_servername(kudu_auth_base64, instance_id, port, password):
    kudu_app = APP_NAME if not SLOT or SLOT.lower() == "production" else f"{APP_NAME}-{SLOT}"
    url = f"https://{kudu_app}.scm.azurewebsites.net/api/command?instance={instance_id}"
    payload = {"command": '/bin/sh -c "echo $COMPUTERNAME"'}
    headers = {"Authorization": f"Basic {kudu_auth_base64}", "Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, data=json.dumps(payload))
    if resp.status_code == 200:
        return resp.json().get("Output", "").strip() or "Unknown"
    # fallback to SSH
    out, _ = await ssh_command(port, password, "echo $COMPUTERNAME || hostname")
    return out.strip() or "Unknown"


# --------------------------------------
# Consistency Check Logic
# --------------------------------------
async def check_file_versions(instance_ids, kudu_auth_base64):
    files_checksum_dict = {}
    instance_servernames = {}

    if not instance_ids:
        console.print("[yellow]⚠️ No instances found.[/yellow]")
        return {}, {}

    for instance_id in instance_ids:
        port, password, tunnel_proc = await get_instance_connection_details(instance_id)
        console.print(f"[cyan]🔗 Connected to instance:[/cyan] {instance_id} on port {port}")
        try:
            server_name = await get_instance_servername(kudu_auth_base64, instance_id, port, password)
            instance_servernames[instance_id] = server_name
            for file in FILES_TO_CHECK:
                full_path = f"/home/site/wwwroot/{file}"
                checksum = await get_file_checksum(port, password, full_path)
                files_checksum_dict.setdefault(file, {}).setdefault(checksum, set()).add(instance_id)
                console.print(f"[green]✔ {file}[/green] → [bold]{checksum}[/bold] ({server_name})")
        finally:
            await close_tunnel(tunnel_proc)

    console.print("[blue]📊 Final checksums:[/blue]")
    console.print(json.dumps({k: {ck: list(v) for ck, v in d.items()} for k, d in files_checksum_dict.items()}, indent=2))
    return files_checksum_dict, instance_servernames


def validate_file_versions(files_checksum_dict, instance_servernames):
    consistent = True
    for file, checksums in files_checksum_dict.items():
        if len(checksums) != 1:
            consistent = False
            console.print(f"[red]❌ Inconsistent file:[/red] {file}")
            for checksum, instances in checksums.items():
                for iid in instances:
                    console.print(f"   - {instance_servernames.get(iid, 'Unknown')} ({iid}) → {checksum}")
    return consistent


# --------------------------------------
# Main
# --------------------------------------
async def main():
    instance_ids, kudu_auth_base64 = get_instance_ids()

    for attempt in range(CONSISTENCY_CHECK_MAX_RETRIES):
        console.rule(f"Attempt {attempt + 1}/{CONSISTENCY_CHECK_MAX_RETRIES}")
        files_checksum_dict, instance_servernames = await check_file_versions(instance_ids, kudu_auth_base64)
        if validate_file_versions(files_checksum_dict, instance_servernames):
            console.print(f"[bold green]\n✅ All {SLOT or 'production'} instances are consistent![/bold green]")
            return
        if attempt < CONSISTENCY_CHECK_MAX_RETRIES - 1:
            console.print(f"[yellow]Retrying in {CONSISTENCY_CHECK_DELAY_IN_SECONDS}s...[/yellow]")
            await asyncio.sleep(CONSISTENCY_CHECK_DELAY_IN_SECONDS)
    raise ValueError("❌ Deployment consistency check failed: inconsistent file versions")


if __name__ == "__main__":
    console.print("[bold blue]🚀 Starting deployment consistency check[/bold blue]")
    try:
        asyncio.get_event_loop().run_until_complete(main())
        console.print("[green]🎉 Consistency check completed successfully[/green]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ {e}[/red]")
        sys.exit(1)
