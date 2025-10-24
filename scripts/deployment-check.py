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
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("SUBSCRIPTION_ID is not set and could not be determined via Azure CLI") from exc

if not FILES_TO_CHECK:
    raise RuntimeError("FILES_TO_CHECK environment variable must be provided (comma separated list)")

FILES_TO_CHECK = [file.strip() for file in FILES_TO_CHECK.split(",") if file.strip()]

USE_CLI_AUTH = os.getenv("USE_CLI_AUTH", "").lower() == "true"

SSH_CONNECTION_RETRY_COUNT = 3
SSH_CONNECTION_DELAY_IN_SECONDS = 2

CONSISTENCY_CHECK_MAX_RETRIES = 5
CONSISTENCY_CHECK_DELAY_IN_SECONDS = 10


def get_cli_token():
    result = subprocess.run(
        ["az", "account", "get-access-token", "--resource", "https://management.azure.com/"],
        capture_output=True,
        text=True,
        check=True,
    )
    token_data = json.loads(result.stdout)
    expires_on = int(
        datetime.strptime(token_data["expiresOn"], "%Y-%m-%d %H:%M:%S.%f").timestamp()
    )
    return AccessToken(token_data["accessToken"], expires_on)


class CLIManagedIdentityCredential:
    def get_token(self, *scopes, **kwargs):
        return get_cli_token()


credential = CLIManagedIdentityCredential() if USE_CLI_AUTH else DefaultAzureCredential()


def get_instance_ids():
    print("Getting instance IDs")
    client = WebSiteManagementClient(credential=credential, subscription_id=SUBSCRIPTION_ID)
    print("Client created")

    options = CsmPublishingProfileOptions(format="WebDeploy")

    if SLOT and SLOT.lower() != "production":
        instances = client.web_apps.list_instance_identifiers_slot(RESOURCE_GROUP, APP_NAME, SLOT)
        publishing_profile = client.web_apps.list_publishing_profile_xml_with_secrets_slot(
            RESOURCE_GROUP,
            APP_NAME,
            SLOT,
            publishing_profile_options=options,
        )
    else:
        instances = client.web_apps.list_instance_identifiers(RESOURCE_GROUP, APP_NAME)
        publishing_profile = client.web_apps.list_publishing_profile_xml_with_secrets(
            RESOURCE_GROUP,
            APP_NAME,
            publishing_profile_options=options,
        )

    publishing_profile_xml = b"".join(publishing_profile).decode("utf-8")

    profile_root = ET.fromstring(publishing_profile_xml)
    msdeploy_profile = profile_root.find(".//publishProfile[@publishMethod='MSDeploy']")
    publishing_user_name = msdeploy_profile.attrib["userName"]
    publishing_user_password = msdeploy_profile.attrib["userPWD"]
    instances_list = [instance.id.split("/")[-1] for instance in instances]
    kudu_auth_base64 = base64.b64encode(f"{publishing_user_name}:{publishing_user_password}".encode()).decode()
    print(f"Discovered instances: {instances_list}")
    return instances_list, kudu_auth_base64


async def get_instance_connection_details(instance_id):
    args = [
        "az",
        "webapp",
        "create-remote-connection",
        "--subscription",
        SUBSCRIPTION_ID,
        "--resource-group",
        RESOURCE_GROUP,
        "--instance",
        instance_id,
        "--name",
        APP_NAME,
    ]

    if SLOT and SLOT.lower() != "production":
        args.extend(["--slot", SLOT])

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    port = None
    password = None

    async for line in proc.stdout:
        decoded = line.decode().strip()
        print("[az]", decoded)
        if port is None:
            match = re.search(r"Opening tunnel on port: (\d+)", decoded)
            if match:
                port = match.group(1)
        if password is None:
            password_match = re.search(r"Password\s*:?\s*(\S+)", decoded, re.IGNORECASE)
            if password_match:
                password = password_match.group(1)
        if port and password:
            break

    if port is None:
        await close_tunnel(proc)
        raise RuntimeError(f"Could not determine remote connection port for instance {instance_id}")

    if password is None:
        await close_tunnel(proc)
        raise RuntimeError(f"Could not determine SSH password for instance {instance_id}")

    return port, password, proc


async def get_file_checksum(port, password, file):
    command = f"md5sum {file}"
    ssh_cmd = [
        "sshpass",
        "-p",
        password,
        "ssh",
        "root@127.0.0.1",
        "-m",
        "hmac-sha1",
        "-p",
        str(port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        command,
    ]

    for attempt in range(SSH_CONNECTION_RETRY_COUNT):
        proc = await asyncio.create_subprocess_exec(
            *ssh_cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        output_lines = stdout.decode().split("\n")
        print(f"md5sum command output: {output_lines}")
        checksum_line = next(
            (line for line in output_lines if re.match(r"^[a-fA-F0-9]{32}\s+.+", line)),
            None,
        )

        if checksum_line:
            return checksum_line.split()[0]

        print(f"Retrying in {SSH_CONNECTION_DELAY_IN_SECONDS:.1f}s")
        await asyncio.sleep(SSH_CONNECTION_DELAY_IN_SECONDS)

    raise RuntimeError(
        f"Error: Could not find checksum in output lines after {SSH_CONNECTION_RETRY_COUNT} retries."
    )


async def get_instance_servername(kudu_auth_base64, instance_id):
    kudu_app = APP_NAME

    if SLOT and SLOT.lower() != "production":
        kudu_app = f"{kudu_app}-{SLOT}"

    url = f"https://{kudu_app}.scm.azurewebsites.net/api/command?instance={instance_id}"
    command = {"command": '/bin/sh -c "echo $COMPUTERNAME"'}
    headers = {
        "Authorization": f"Basic {kudu_auth_base64}",
        "Content-Type": "application/json",
    }
    response = requests.post(url, headers=headers, data=json.dumps(command))
    if response.status_code != 200:
        print("Error:", response.status_code, response.text)
        print("Could not find servername")
        return "Unknown"
    output = response.json().get("Output", "").strip()
    print(f"Server Name: {output}")
    return output


async def close_tunnel(proc):
    if proc.returncode is not None:
        return

    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=2)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()


async def check_file_versions(instance_ids, kudu_auth_base64):
    files_checksum_dict = {}
    instance_servernames = {}

    if not instance_ids:
        print("No instances to process.")
    else:
        print(f"Processing {len(instance_ids)} instances...")

    for instance_id in instance_ids:
        port, password, tunnel_proc = await get_instance_connection_details(instance_id)
        print(f"Remote connection to {instance_id} on port: {port}")

        server_name = await get_instance_servername(kudu_auth_base64, instance_id)
        instance_servernames[instance_id] = server_name

        try:
            for file in FILES_TO_CHECK:
                files_checksum_dict.setdefault(file, {})
                print(f"Running checksum on: {file}")
                full_path = f"/home/site/wwwroot/{file}"
                checksum = await get_file_checksum(port, password, full_path)
                files_checksum_dict[file].setdefault(checksum, set()).add(instance_id)
                print(
                    "Instance: %s | Server Name: %s | File: %s | Checksum: %s"
                    % (instance_id, server_name, file, checksum)
                )
        finally:
            await close_tunnel(tunnel_proc)

    print(
        "Final checksums by file:",
        json.dumps({k: {ck: list(v) for ck, v in d.items()} for k, d in files_checksum_dict.items()}, indent=2),
    )

    return files_checksum_dict, instance_servernames


def validate_file_versions(files_checksum_dict, instance_servernames):
    is_consistent = True
    for file, checksums in files_checksum_dict.items():
        if len(checksums) != 1:
            is_consistent = False
            print(f"File {file} has different versions across the instances:")
            for checksum, instances in checksums.items():
                formatted_instances = [
                    f"Server: {instance_servernames.get(instance_id, 'Unknown')} (ID: {instance_id})"
                    for instance_id in instances
                ]
                print(
                    f"   Checksum: {checksum}, Instances:\n\t\t "
                    + ",\n\t\t".join(formatted_instances)
                )
    return is_consistent


async def main():
    instance_ids, kudu_auth_base64 = get_instance_ids()

    for attempt in range(CONSISTENCY_CHECK_MAX_RETRIES):
        attempt_number = attempt + 1

        if attempt > 0:
            print("\n" + "=" * 10)
            print(
                f"Retrying consistency check (Attempt {attempt_number}/{CONSISTENCY_CHECK_MAX_RETRIES})"
            )
            print(
                f"Waiting {CONSISTENCY_CHECK_DELAY_IN_SECONDS} seconds before retry"
            )
            print("\n" + "=" * 10)
            await asyncio.sleep(CONSISTENCY_CHECK_DELAY_IN_SECONDS)
        else:
            print(
                f"Running consistency check (Attempt {attempt_number}/{CONSISTENCY_CHECK_MAX_RETRIES})"
            )

        files_checksum_dict, instance_servernames = await check_file_versions(
            instance_ids, kudu_auth_base64
        )
        is_consistent = validate_file_versions(files_checksum_dict, instance_servernames)

        if is_consistent:
            print(
                f"\nAll {SLOT or 'production'} instances have consistent versions for verified files"
            )
            print(
                f"Consistency check passed on attempt {attempt_number}/{CONSISTENCY_CHECK_MAX_RETRIES}"
            )
            return
        elif attempt < CONSISTENCY_CHECK_MAX_RETRIES - 1:
            print("\nInconsistency detected. Will retry")
        else:
            break

    raise ValueError(
        "Deployment consistency check failed: File versions are inconsistent across instances"
    )


if __name__ == "__main__":
    print("Starting deployment consistency check")
    try:
        asyncio.get_event_loop().run_until_complete(main())
        print("Successfully ran deployment consistency check")
    except RuntimeError as exc:
        if "Event loop is closed" not in str(exc):
            raise
