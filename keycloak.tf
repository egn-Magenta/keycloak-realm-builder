terraform {
  backend "pg" {}
  required_providers {
    keycloak = {
      source = "mrparkers/keycloak"
      version = "3.6.0"
    }
  }
}

variable "keycloak_admin_client_id" {
  type        = string
  description = ""
  default     = "admin-cli"
}

variable "keycloak_admin_username" {
  type        = string
  description = ""
  default     = "admin"
}

variable "keycloak_admin_password" {
  type        = string
  description = ""
}

variable "keycloak_url" {
  type        = string
  description = ""
  default     = "http://localhost:8081"
}

variable "keycloak_realm_display_name" {
  type        = string
  description = ""
}

variable "keycloak_mo_client_redirect_uri" {
  type        = list(string)
  description = ""
}

variable "keycloak_egir_client_redirect_uri" {
  type        = list(string)
  description = ""
}

variable "keycloak_mo_client_web_origin" {
  type        = list(string)
  description = ""
}

variable "keycloak_egir_client_web_origin" {
  type        = list(string)
  description = ""
}

variable "keycloak_dipex_client_enabled" {
  type        = bool
  description = ""
}

variable "keycloak_dipex_client_secret" {
  type        = string
  description = ""
  sensitive   = true
}

variable "keycloak_egir_client_enabled" {
  type        = bool
  description = ""
}

variable "keycloak_egir_client_secret" {
  type        = string
  description = ""
  sensitive   = true
}

variable "keycloak_realm_users" {
  type        = list(object({
    username = string
    password = string
    firstname = string
    lastname = string
    email = string
    roles = list(string)
    enabled = bool
  }))
  description = ""
}

variable "keycloak_idp_enable" {
  type        = bool
  description = ""
}

#variable "keycloak_idp_encryption_key" {
#  type        = string
#  description = ""
#}

variable "keycloak_idp_signing_certificate" {
  type        = string
  description = ""
}

variable "keycloak_idp_signed_requests" {
  type        = bool
  description = ""
}

variable "keycloak_idp_name_id_policy_format" {
  type        = string
  description = ""
}

variable "keycloak_idp_entity_id" {
  type        = string
  description = ""
}

variable "keycloak_idp_logout_service_url" {
  type        = string
  description = ""
}

variable "keycloak_idp_signon_service_url" {
  type        = string
  description = ""
}

variable "keycloak_ssl_required" {
  type        = string
  description = ""
}

provider "keycloak" {
    client_id     = var.keycloak_admin_client_id
    username      = var.keycloak_admin_username
    password      = var.keycloak_admin_password
    url           = var.keycloak_url
}

# Realms
resource "keycloak_realm" "mo" {
  realm             = "mo"
  enabled           = true
  display_name      = var.keycloak_realm_display_name
  ssl_required      = var.keycloak_ssl_required
}

resource "keycloak_realm" "lora" {
  realm             = "lora"
  enabled           = true
  display_name      = "LoRa"
  ssl_required      = var.keycloak_ssl_required
}

# Roles
resource "keycloak_role" "admin" {
  realm_id    = keycloak_realm.mo.id
  name        = "admin"
  description = "Write access to everything in MO"
}

resource "keycloak_role" "owner" {
  realm_id    = keycloak_realm.mo.id
  name        = "owner"
  description = "Only write access to units of which the user is owner in MO"
}

resource "keycloak_role" "read_org" {
  realm_id    = keycloak_realm.mo.id
  name        = "read_org"
  description = "Read access to organisation in MO"
}

resource "keycloak_role" "read_org_unit" {
  realm_id    = keycloak_realm.mo.id
  name        = "read_org_unit"
  description = "Read access to organisation unit(s) in MO"
}

resource "keycloak_role" "read_employee" {
  realm_id    = keycloak_realm.mo.id
  name        = "read_employee"
  description = "Read access to employee(s) in MO"
}

resource "keycloak_role" "reader" {
  realm_id    = keycloak_realm.mo.id
  name        = "reader"
  description = "Read access to everything in MO"
  composite_roles = [
    keycloak_role.read_org.id,
    keycloak_role.read_org_unit.id,
    keycloak_role.read_employee.id,
  ]
}

locals {
    roles = {
        reader = keycloak_role.reader.id
        read_employee = keycloak_role.read_employee.id
        read_org_unit = keycloak_role.read_org_unit.id
        read_org = keycloak_role.read_org.id
        owner = keycloak_role.owner.id
        admin = keycloak_role.admin.id
    }
}

# Clients

resource "keycloak_openid_client" "mo" {
  realm_id            = keycloak_realm.mo.id
  client_id           = "mo"
  enabled             = true

  name                = "OS2mo Frontend"
  access_type         = "PUBLIC"
  standard_flow_enabled = true

  valid_redirect_uris = var.keycloak_mo_client_redirect_uri
  web_origins         = var.keycloak_mo_client_web_origin
}

resource "keycloak_openid_client" "egir" {
  realm_id            = keycloak_realm.mo.id
  client_id           = "egir"
  enabled             = var.keycloak_egir_client_enabled

  name                = "EGIR"
  access_type         = "PUBLIC"
  standard_flow_enabled = true

  client_secret       = var.keycloak_egir_client_secret

  valid_redirect_uris = var.keycloak_egir_client_redirect_uri
  web_origins         = var.keycloak_egir_client_web_origin
}

resource "keycloak_openid_client" "dipex" {
  realm_id            = keycloak_realm.mo.id
  client_id           = "dipex"
  enabled             = var.keycloak_dipex_client_enabled

  name                = "DIPEX"
  access_type         = "CONFIDENTIAL"
  service_accounts_enabled = true

  client_secret       = var.keycloak_dipex_client_secret
}

# Users
resource "keycloak_user" "mo_user" {
  realm_id = keycloak_realm.mo.id
  username = each.value.username
  enabled  = each.value.enabled

  email      = each.value.email
  first_name = each.value.firstname
  last_name  = each.value.lastname

  initial_password {
    value     = each.value.password
  }

  for_each   = {for user in var.keycloak_realm_users: user.username => user}
}

# User roles
resource "keycloak_user_roles" "mo_user_roles" {
  realm_id = keycloak_realm.mo.id
  user_id  = keycloak_user.mo_user[each.key].id

  role_ids = [for role in each.value.roles: lookup(local.roles, role)]

  for_each   = {for user in var.keycloak_realm_users: user.username => user}
}

# IDP
resource "keycloak_saml_identity_provider" "adfs" {
  realm = keycloak_realm.mo.id
  alias = "adfs-saml"
  enabled = var.keycloak_idp_enable

  # TODO: encryption key?
  signing_certificate = var.keycloak_idp_signing_certificate
  want_assertions_signed = var.keycloak_idp_signed_requests
  # name_id_policy_format = var.keycloak_idp_name_id_policy_format
  name_id_policy_format = "Persistent"

  entity_id                  = var.keycloak_idp_entity_id
  single_sign_on_service_url = var.keycloak_idp_signon_service_url
  single_logout_service_url  = var.keycloak_idp_logout_service_url
}
