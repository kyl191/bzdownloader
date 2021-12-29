#!/usr/bin/env python3
import argparse
import configparser
import hashlib
import logging
import sys
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta
from io import BytesIO, SEEK_END
from typing import List, Optional
from pathlib import Path

# replace with https://pypi.org/project/defusedxml/?
from xml.etree.ElementTree import fromstring

import questionary
import requests
from humanize.filesize import naturalsize
from tqdm import tqdm

json_headers = {
    "User-Agent": "backblaze_agent/8.0.1.567",
    "Accept": "*/*",
    "Content-Type": "application/x-www-form-urlencoded",
}

# The Backblaze dateformat - stored in UTC
# Ugly, but keeping one format to reduce confusion
date_format = "d%Y%m%d_m%H%M%S"

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)


@dataclass
class Restore:
    serverhost: str  # eg restore-sac0-0004
    display_filename: str  # eg hostname_datestamp.zip
    hguid: str  # hex numbers, host guid?
    rid: str  # decimal numbers, presumably restore ID?
    state: str  # "available" or something else
    zipsize: int


class BzDownloader:
    def __init__(self, config_filename: str):
        self.chunk_size = 1024 ** 2 * 20  # 20MB chunks by default
        self.config_filename = config_filename
        self.config = configparser.ConfigParser()
        config_file = Path(config_filename)
        if config_file.is_file():
            self.config.read(config_file)

        # setup some basic defaults
        if "session" not in self.config.sections():
            self.config["session"] = {
                "expiry": datetime.fromtimestamp(0).strftime(date_format)
            }
        if "auth" not in self.config.sections():
            self.config["auth"] = {}

    @property
    def auth_token(self):
        return self.config["session"]["auth_token"]

    @property
    def email(self):
        return self.config["auth"]["email"]

    @property
    def cluster(self):
        return self.config["session"]["cluster"]

    def is_session_valid(self) -> bool:
        # If we have no token, obviously not valid
        if "auth_token" not in self.config["session"]:
            return False
        # We need the cluster to be set to determine what Cluster Admin (?) to connect to
        if "cluster" not in self.config["session"]:
            return False
        # Consider the session to be expired if there's only 5 minutes left
        expiry = datetime.fromtimestamp(0)
        if "expiry" in self.config["session"]:
            expiry = datetime.strptime(self.config["session"]["expiry"], date_format)
        return expiry > datetime.utcnow() - timedelta(minutes=5)

    def reauth(self):
        """
        Force a reauth using stored email & password, if present
        """
        if "email" not in self.config["auth"]:
            self.config["auth"]["email"] = questionary.text(
                "Backblaze email address?"
            ).ask()
        else:
            log.info(f'Using stored email for auth: {self.config["auth"]["email"]}')
        if "password" not in self.config["auth"]:
            # Not encrypting, but random characters trip up the parser (eg '%')
            # We need to convert to bytes for the encode, and then decode to string to store in the config ini
            # Stupid? Yes. Works? Also yes.
            password = b64encode(
                questionary.password("Backblaze password?").ask().encode("utf-8")
            ).decode("ascii")
            self.config["auth"]["password"] = password
        else:
            log.info("Using stored password for auth: <redacted>")

        session = self.create_session(self.config["auth"]["email"])

        while session.get("challenge") is not None:
            kind = session.get("challenge", {}).get("challengeType", "")
            log.debug(f"Next challenge type: {kind}")
            if kind == "totp":
                value = questionary.text("Backblaze TOTP code?").ask()
            else:
                value = b64decode(self.config["auth"]["password"]).decode("utf-8")

            session = self.present_credentials(
                kind=kind,
                value=value,
                auth_token=session.get("authToken"),
                api_url=session.get("apiUrl"),
            )

        if not session.get("isAuthenticated"):
            raise RuntimeError("Challenges completed, but failed to authenticate")

        self.config["session"]["auth_token"] = session.get("authToken")
        self.config["session"]["expiry"] = session.get("sessionExpires")
        self.config["session"]["cluster"] = (
            session.get("info", {}).get("accountProfile", {}).get("clusterNum")
        )

        with open(self.config_filename, "w") as configfile:
            self.config.write(configfile)

    @staticmethod
    def create_session(email):
        """
        Trigger the session creation
        """
        payload = {
            "identity": {"identityType": "accountEmail", "email": email},
            "clientInfo": {
                "deviceName": "bzclient",
                "clientType": "com/backblaze/backup/win",
            },
        }
        url = "https://api.backblazeb2.com/b2api/v1/b2_create_session"
        r = requests.post(url, headers=json_headers, json=payload)

        if not r.ok:
            r.raise_for_status()
        result = r.json()
        if not result.get("challenge", {}).get("challengeType", "") == "password":
            raise RuntimeError(
                f"Unsupported next challenge type {result.get('challenge', {})}, bailing"
            )

        return result

    @staticmethod
    def present_credentials(kind, value, auth_token, api_url):
        # Same API endpoint for both password and totp, but the payload field name changes
        # So we need this mapping of cred type to field name
        field_names = {
            "password": "password",
            "totp": "code",
        }
        # I'm not sure if there are credential types other than these two, anything else is unsupported
        if kind not in field_names.keys():
            raise RuntimeError(
                f"Unsupported credentials {kind}, not in {', '.join(field_names.keys())}"
            )

        payload = {
            "credentials": {"credentialsType": kind, field_names[kind]: value},
            "infoRequested": ["accountProfile"],
            "authToken": auth_token,
        }
        url = f"{api_url}/b2api/v1/b2_present_credentials"
        r = requests.post(url, headers=json_headers, json=payload)

        if not r.ok:
            r.raise_for_status()
        result = r.json()

        # If challenge is not empty, or it's not a supported kind, bail
        if (
            result.get("challenge")
            and not result.get("challenge", {}).get("challengeType", "")
            in field_names.keys()
        ):
            raise RuntimeError(
                f"Unsupported next challenge type {result.get('challenge', {})}, bailing"
            )

        return result

    def get_list_of_restores(self):
        url = f"https://ca{self.cluster}.backblaze.com/api/restoreinfo"
        headers = {
            "User-Agent": "backblaze_agent/8.0.1.567",
            "Accept": "*/*",
            "Authorization": self.auth_token,
        }
        payload = {
            "version": "8.0.1.567",
            "hexemailaddr": bytes.hex(self.email.encode("ascii")),
            "bz_v5_auth_token": self.auth_token,
            # 500 error when these aren't passed for some reason
            "hexpassword": "none",
            "twofactorverifycode": "none",
            "hexsecondfactor": "none",
            "bz_auth_token": "none",
            # ???
            "bzsanity": "7e33",
        }

        r = requests.post(url, headers=headers, data=payload)
        if not r.ok:
            r.raise_for_status()
        res = fromstring(r.text)
        status = res.find("response")
        # bool(status) is False even when it has a value, so we have to explictly check for None
        if status is None:
            log.info(f"Failed to find response in returned XML: {r.text}")
            raise RuntimeError(
                "Expected 'response' item not found in XML list of restores, bailing"
            )
        if status.attrib.get("result", "").lower() != "true":
            raise RuntimeError(
                f"Failed to fetch XML list of restores, reason: {status.attrib.get('reason')}"
            )

        restores = res.findall("restore")
        log.info(f"Found {len(restores)} restores")

        processed_restores: List[Restore] = []
        for restore in restores:
            attr = restore.attrib
            r = Restore(
                serverhost=attr.get("serverhost"),
                display_filename=attr.get("display_filename"),
                hguid=attr.get("hguid"),
                rid=attr.get("rid"),
                state=attr.get("state"),
                zipsize=int(attr.get("zipsize")),
            )
            processed_restores.append(r)
        return processed_restores

    @staticmethod
    def select_restores(restores: List[Restore]) -> List[Restore]:
        choices = [
            questionary.Choice(
                title=f"{r.display_filename} ({naturalsize(r.zipsize)})",
                value=r,
                disabled=None if r.state.lower() == "available" else r.state,
            )
            for r in restores
        ]
        return questionary.checkbox("Select restores to download", choices).ask()

    @staticmethod
    def handle_metadata_prelude(chunk: bytes) -> bytes:
        ok = True

        # bzftp001t_aaaaaa prelude
        if chunk[0:8] == b"bzftp001":
            log.debug(f"bzftp001 prelude: Slicing off {chunk[0:16]}")
            if chunk[8:16] != b"t_aaaaaa":
                log.info(f"bzftp001: Expected t_aaaaaa, got {chunk[8:16]}")
            chunk = chunk[16:]
        else:
            log.debug(f"bzftp001 prelude not found, found {chunk[0:16]} instead")
            ok = False

        # bzftp002 prelude
        if chunk[0:8] == b"bzftp002":
            log.debug(f"bzftp002 prelude: Slicing off {chunk[0:8]}")
            chunk = chunk[8:]
        else:
            log.debug(f"bzftp002 prelude not found, found {chunk[0:8]} instead")
            ok = False

        if not ok:
            raise RuntimeError(
                f"error trimming metadata prelude `{chunk[0:24]}`, failing for safety"
            )
        return chunk

    @staticmethod
    def handle_metadata_postlude(remnant: BytesIO) -> str:
        """
        Returns the sha1sum extracted from the remnant of the download chunk
        """
        ok = True
        if len(remnant.getvalue()) != 56:
            log.warning(
                f"Remnant doesn't match expected 56 bytes length, is {len(remnant.getvalue())} bytes long"
            )
            ok = False

        # bzftpend postlude
        remnant.seek(-8, SEEK_END)
        fbytes = remnant.read(8)
        if fbytes == b"bzftpend":
            log.debug("postlude: found bzftpend")
        else:
            log.warning(f"bzftpend postlude not found, found {fbytes} instead")
            ok = False

        # Extract the sha1sum - from the start of the remnant
        remnant.seek(0)
        fbytes = remnant.read(8)
        sha1sum = ""
        if fbytes == b"bzftpsha":
            log.debug("postlude: Extracting bzftpsha value")
            sha1sum = remnant.read(40).decode("ascii")
        else:
            log.warning(f"bzftpsha postlude not found, found {fbytes} instead")
            ok = False

        if not ok:
            raise RuntimeError(
                f"error extracting sha1sum from metadata postlude `{remnant.getvalue()}`, failing for safety"
            )
        return sha1sum

    @staticmethod
    def select_destination(filename: str) -> Path:
        dest_path = (Path(".") / filename).resolve()
        print(f"Currently saving to {dest_path}")
        dest = questionary.path(
            f"Where should {filename} be saved? (Type ../ to go up a directory, enter to accept the default)",
            only_directories=True,
        ).ask()
        dest_path = Path(dest)
        if not dest_path.is_absolute():
            dest_path = Path(".") / Path(dest)
        dest_path = (dest_path / filename).resolve()

        # Handle file already exists by adding a (1) suffix to the file name
        if dest_path.is_file():
            # implicitly starts count at 1 because dest_path isn't reset before entering the while loop
            count = 0
            stem = dest_path.stem
            suffix = "".join(dest_path.suffixes)
            while dest_path.is_file():
                count += 1
                dest_path = dest_path.with_name(f"{stem} ({count}){suffix}")

        print(f"Will save to {dest_path}")
        return dest_path

    def download_restore(self, restore: Restore, dest_path: Path):
        url = f"https://{restore.serverhost}.backblaze.com/api/restorezipdownloadex"
        headers = {
            "User-Agent": "backblaze_agent/8.0.1.567",
            "Accept": "*/*",
            "Authorization": self.auth_token,
        }
        payload = {
            "version": "8.0.1.567",
            "hexemailaddr": bytes.hex(self.email.encode("ascii")),
            "hexpassword": bytes.hex("null".encode("ascii")),
            "bz_v5_auth_token": self.auth_token,
            "bzsanity": "7e33",  # ??? No clue what this value is
            "hguid": restore.hguid,
            "rid": restore.rid,
        }

        s = requests.Session()
        s.headers.update(headers)

        """
        The server computes a sha1sum for each segment.
        Follow the downloader convention of chunking in the case it loads the entire chunk into memory,
        if we requested a 500GB zip at once it might OOM the server process.
        """
        download_bar = tqdm(
            total=int(restore.zipsize), unit_scale=True, unit_divisor=1024, unit="B"
        )
        for byte_index in range(0, int(restore.zipsize), self.chunk_size):
            expected_byte_count = min(
                self.chunk_size, int(restore.zipsize) - byte_index
            )
            payload["request_firstbyteindex"] = byte_index
            payload["request_numbytes"] = expected_byte_count

            r = s.post(url, data=payload, stream=True)
            if int(r.headers["Content-Length"]) - expected_byte_count != 80:
                raise RuntimeError(
                    f'Expected 80 bytes of metadata, appear to have {int(r.headers["Content-Length"]) - expected_byte_count} '
                    "bytes instead, bailing"
                )

            """
            The download process is complicated because BZ does things to the downloaded file segments
            There's a 24 byte metadata prelude - bzftp001t_aaaaaabzftp002
            And a trailing 56 byte metadata postlude - bzftpsha<40bytesha1sum>bzftpend

            For the bzftp001 prelude, I haven't seen a value other than t_aaaaaa, I'm guessing it's legacy
            """
            prelude_done = False
            sha1 = hashlib.sha1()
            remnant = BytesIO()
            with open(dest_path, "ab") as fd:
                # can't use fd.tell() because we want the relative offset from the 1st byte we downloaded
                current_offset = 0

                log.debug("Starting download")
                for chunk in r.iter_content(chunk_size=1024 ** 2):
                    log.debug(f"Got {len(chunk)} bytes")

                    # Handle the metadata prelude
                    if not prelude_done:
                        chunk = self.handle_metadata_prelude(chunk)
                        prelude_done = True
                        log.debug(f"prelude finished: chunk now {len(chunk)} bytes")

                    """
                    If we have more data than expected, put the remainder in the `remnant` IO buffer

                    This also handles the "postlude is across multiple chunks" case
                    expected_byte_count - current_offset will go negative, so final byte will be set to 0
                    sha1update with an empty string doesn't change the digest
                    fd.write with an empty string won't write any bytes
                    """
                    if expected_byte_count - (current_offset + len(chunk)) <= 0:
                        final_byte = max(0, expected_byte_count - current_offset)
                        remnant.write(chunk[final_byte:])
                        chunk = chunk[0:final_byte]

                    sha1.update(chunk)
                    bytes_written = fd.write(chunk)
                    if len(chunk) != bytes_written:
                        log.warning(
                            f"Wrote {bytes_written} bytes but expected to write {len(chunk)} bytes"
                        )
                    download_bar.update(bytes_written)
                    current_offset += bytes_written
                    log.debug(f"Wrote {bytes_written} bytes")

            sha1sum = self.handle_metadata_postlude(remnant)
            if sha1sum == sha1.hexdigest():
                log.debug(f"Expected sha1sum matches actual: {sha1sum}")
            else:
                log.warning(
                    f"Expected sha1sum ({sha1sum}) doesn't match actual sha1sum: {sha1.hexdigest()}"
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Download restore files from Backblaze Personal Backup"
    )
    parser.add_argument(
        "--config_filename",
        help="path to config file",
        default="bzdownloader_config.ini",
    )
    parser.add_argument("--verbose", "-v", action="count", default=0)
    args = parser.parse_args()
    if args.verbose > 0:
        if args.verbose == 1:
            log.setLevel(logging.INFO)
        else:
            log.setLevel(logging.DEBUG)

    dl = BzDownloader(args.config_filename)
    if not dl.is_session_valid():
        dl.reauth()
    else:
        print(f"Logged in as {dl.email}")

    restores = dl.get_list_of_restores()
    if len(restores) == 0:
        print("No restores found, exiting")
        sys.exit()

    selected = dl.select_restores(restores)
    if len(selected) == 0:
        print("No restores selected, exiting")
        sys.exit()
    # Front load all the interactive work of downloading
    dests = {
        dl.select_destination(restore.display_filename): restore for restore in selected
    }
    for dest_path, restore in dests.items():
        print(f"Downloading {restore.display_filename} to {str(dest_path)}:")
        start = time.perf_counter()
        dl.download_restore(restore, dest_path)
        end = time.perf_counter()
        duration = end - start
        print(f"Took {duration:.2f} secs to download {restore.zipsize} bytes")
