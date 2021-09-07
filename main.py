# SPDX-FileCopyrightText: Magenta ApS
#
# SPDX-License-Identifier: MPL-2.0
import json
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Literal
from typing import Optional
from typing import Union
from uuid import UUID
from uuid import uuid4

import click
from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import Template
from pydantic import AnyHttpUrl
from pydantic import BaseModel
from pydantic import BaseSettings
from pydantic import EmailStr
from pydantic import Field
from pydantic import FilePath
from pydantic import parse_obj_as
from pydantic import PositiveInt
from pydantic import root_validator
from pydantic import validator


class Roles(str, Enum):
    admin = "admin"
    owner = "owner"


class KeycloakUser(BaseModel):
    username: str
    password: str
    firstname: str
    lastname: str
    email: EmailStr
    uuid: UUID = Field(None)
    roles: List[Roles] = []
    enabled: bool = True

    # Autogenerate UUID if necessary
    @validator("uuid", pre=True, always=True)
    def set_uuid(cls, _uuid: Optional[UUID]) -> UUID:
        return _uuid or uuid4()


class Settings(BaseSettings):
    # Keycloak version
    # Note: We currently use version 13.0.0 in the dev env
    keycloak_version: str = "14.0.0"

    # Display name shown on the main Keycloak user login page
    keycloak_realm_display_name: str = "OS2mo"

    # Frontend page(s) that Keycloak is allowed to redirect users back to after they
    # have authenticated successfully in Keycloak
    keycloak_mo_client_redirect_uri: List[Union[AnyHttpUrl, Literal["*"]]] = [
        parse_obj_as(AnyHttpUrl, "http://localhost:5001/*")
    ]

    keycloak_egir_client_redirect_uri: List[Union[AnyHttpUrl, Literal["*"]]] = [
        parse_obj_as(AnyHttpUrl, "http://localhost:5001/*")
    ]

    # Allowed CORS origins
    keycloak_mo_client_web_origin: List[Union[AnyHttpUrl, Literal["*"]]] = [
        parse_obj_as(AnyHttpUrl, "http://localhost:5001")
    ]

    keycloak_egir_client_web_origin: List[Union[AnyHttpUrl, Literal["*"]]] = [
        parse_obj_as(AnyHttpUrl, "http://localhost:5001")
    ]

    # Toggles DIPEX client enablement. If non-user clients should be allowed to
    # contact Keycloak, the DIPEX client can be used. The client uses a
    # client secret auth mechanism to get OIDC tokens instead of the usual
    # username/password mechanism (see further details in the Sphinx MO docs on
    # the development branch)
    keycloak_dipex_client_enabled: bool = False

    # Fix 45298: We need longer access token lifespan for DIPEX
    # This should be set to the default of 5 minutes when we fix our clients
    # Default: 43200 seconds, i.e. 12 hours
    keycloak_dipex_token_lifespan: PositiveInt = 43200

    # DIPEX client secret that can be used to obtain an OIDC token
    # For an example, see:
    # * https://git.magenta.dk/rammearkitektur/os2mo/-/blob/development/backend/ \
    #       tests/manual/keycloak-client-secret.py
    keycloak_dipex_client_secret: Optional[str]

    # Toggles EGIR client enablement
    keycloak_egir_client_enabled: bool = False

    # The EGIR client secret
    keycloak_egir_client_secret: Optional[str]

    # The MO realm will have the users below auto-provisioned
    # which can be handy for testing purposes
    keycloak_realm_users: Optional[List[KeycloakUser]] = []

    # RBAC
    keycloak_rbac_enabled: bool = False

    # IDP Configuration
    keycloak_idp_enable: bool = False
    keycloak_idp_encryption_key: Optional[str]
    keycloak_idp_signing_certificate: Optional[str]
    keycloak_idp_signed_requests: bool = False
    keycloak_idp_name_id_policy_format: str = (
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    keycloak_idp_entity_id: Optional[AnyHttpUrl]
    keycloak_idp_logout_service_url: Optional[AnyHttpUrl]
    keycloak_idp_signon_service_url: Optional[AnyHttpUrl]

    # Specifies whether SSL is required for Keycloak requests. Can be one of
    # "all", "external" or "none". The options are further described here:
    # https://www.keycloak.org/docs/latest/server_installation/#_setting_up_ssl
    keycloak_ssl_required: str = "all"

    # LoRa
    keycloak_lora_realm_enabled: bool = False
    keycloak_lora_client_secret: Optional[str]

    @root_validator
    def optionally_required(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Check that derived keys are set if master switch is set."""
        optionally_required_fields = {
            "keycloak_idp_enable": (
                "keycloak_idp_encryption_key",
                "keycloak_idp_signing_certificate",
                "keycloak_idp_entity_id",
                "keycloak_idp_logout_service_url",
                "keycloak_idp_signon_service_url",
            ),
            "keycloak_dipex_client_enabled": ("keycloak_dipex_client_secret",),
            "keycloak_egir_client_enabled": ("keycloak_egir_client_secret",),
            "keycloak_lora_realm_enabled": ("keycloak_lora_client_secret",),
        }
        for main_key, required_keys in optionally_required_fields.items():
            if not values[main_key]:
                continue
            for required_key in required_keys:
                if required_key not in values:
                    raise ValueError(f"{required_key} not set")
                if values[required_key] is None:
                    raise ValueError(f"{required_key} is None")
        return values


def quote(s: str) -> str:
    """
    Template filter function adding quotes
    """
    return f'"{s}"'


@lru_cache(maxsize=None)
def get_settings() -> Settings:
    return Settings()


def get_template(path: FilePath) -> Template:
    loader = FileSystemLoader(searchpath=".")
    env = Environment(loader=loader)
    env.filters["quote"] = quote
    return env.get_template(str(path))


def write_file(path: Path, contents: str) -> None:
    with open(path, "w") as output_file:
        output_file.write(contents)


def generate_file(template_path: FilePath, output_path: Path, dry_run: bool) -> None:
    settings = get_settings()

    template = get_template(template_path)
    result = template.render(**settings.dict())
    # Verify that valid JSON was generated
    json.loads(result)
    # content = json.dumps(payload, indent=4, sort_keys=True)
    if dry_run:
        print(result)
    else:
        write_file(output_path, result)


@click.command()
@click.option(
    "--keycloak_realm_json_path",
    type=click.Path(writable=True, dir_okay=False),
    default="/srv/keycloak-realm.json",
    help="Output file location for keycloak-realm.json",
    show_default=True,
    envvar="KEYCLOAK_REALM_JSON_PATH",
)
@click.option(
    "--keycloak_realm_json_template_path",
    type=click.Path(exists=True, dir_okay=False),
    default="keycloak-realm.json.j2",
    help="Input template file location for keycloak-realm.json",
    show_default=True,
    envvar="KEYCLOAK_REALM_JSON_TEMPLATE_PATH",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print output to stdout instead of file",
)
def main(
    keycloak_realm_json_path: Path,
    keycloak_realm_json_template_path: Path,
    dry_run: bool,
) -> None:
    generate_file(
        keycloak_realm_json_template_path,
        keycloak_realm_json_path,
        dry_run,
    )


if __name__ == "__main__":
    main()
