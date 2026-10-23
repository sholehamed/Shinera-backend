#!/usr/bin/env python3
"""Real OpenIddict HTTP authorization matrix against a disposable Development SQL Server.

Runs after the API is started by backend-sqlserver-ci.yml. No mocks, forged
server identities, TestServer shortcuts, third-party modules or credentials
embedded in the test. A failed assertion exits nonzero and fails GitHub Actions.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = os.environ.get("SHINERA_E2E_BASE_URL", "http://127.0.0.1:5069").rstrip("/")
PASSWORD = os.environ["SHINERA_DEVELOPMENT_ADMIN_PASSWORD"]
GROUP_ID = "7fbf4183-c8ab-4e2e-805d-65fd7fa95247"
PERMISSION_ID = "45129362-d8b8-4bde-8600-98745e311923"
FOREIGN_ID = "00000000-0000-0000-0000-000000000001"
PASSED = 0


def request(method, path, token=None, data=None, headers=None):
    """Return status and response bytes, including HTTP error bodies."""
    h = dict(headers or {})
    if token is not None:
        h["Authorization"] = "Bearer " + token
    if isinstance(data, (dict, list)):
        body = json.dumps(data).encode("utf-8")
        h["Content-Type"] = "application/json"
    elif isinstance(data, bytes):
        body = data
    else:
        body = None
    req = urllib.request.Request(BASE + path, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def check(method, path, expected, *, token=None, data=None, headers=None):
    global PASSED
    code, body = request(method, path, token=token, data=data, headers=headers)
    if code != expected:
        # Never log request headers or bearer tokens to CI output.
        raise AssertionError(
            f"{method} {path}: expected HTTP {expected}, got {code}; "
            f"response={body.decode('utf-8', 'replace')[:350]}")
    PASSED += 1
    print(f"PASS [{PASSED:02d}] {method} {path} -> {code}", flush=True)
    return body


def claims_of(jwt):
    # This is ONLY metadata inspection to select the seed account's subject ID.
    # The authorization decision is made by the API validating the signed token.
    parts = jwt.split(".")
    if len(parts) != 3:
        raise AssertionError("Expected signed, non-encrypted OpenIddict JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def login(username, context, tenant=None):
    challenge_bytes = check("GET", "/api/system/Auth/captcha/new", 200)
    challenge = json.loads(challenge_bytes)
    form = {
        "grant_type": "password",
        "client_id": "postman",
        "username": username,
        "password": PASSWORD,
        "login_context": context,
        "scope": "openid profile email api offline_access",
        "captchaid": challenge["token"],
        "userEnteredCaptchaCode": "ABCDE",
    }
    if tenant:
        form["tenant"] = tenant
    body = urllib.parse.urlencode(form).encode("ascii")
    result = check("POST", "/api/system/Auth/login", 200,
                   data=body,
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
    access_token = json.loads(result)["access_token"]
    claims = claims_of(access_token)
    assert claims.get("account_type") == context, "Wrong account_type from login"
    assert uuid.UUID(claims["sub"]), "Missing or invalid subject ID"
    if context == "system":
        assert "tenant_id" not in claims, "System user must never have tenant_id"
    return access_token, str(uuid.UUID(claims["sub"]))


def json_value(body):
    return json.loads(body.decode("utf-8"))


def run():
    print("Running disposable SQL Server + real OpenIddict HTTP security matrix", flush=True)
    admin, admin_id = login("admin", "system")
    viewer, viewer_id = login("e2e-viewer", "system")
    tenant, tenant_id = login("e2e-tenant", "tenant", "e2e-http-ci")
    assert admin_id != viewer_id != tenant_id

    roles = "/api/system/Roles"
    users = "/api/system/Users"
    groups = "/api/system/Groups"
    perms = "/api/system/Permissions"
    role_payload = {"name": "E2E HTTP Scoped Operator",
                    "description": "Disposable authorization test", "isActive": True}

    # Both read and write paths enforce the HTTP authentication boundary.
    check("GET", roles + "/lookup", 401)
    check("POST", roles, 401, data=role_payload)
    check("GET", roles + "/lookup", 401, token="invalid.signature.token")
    check("GET", roles + "/lookup", 403, token=viewer)
    check("POST", roles, 403, token=viewer, data=role_payload)
    check("GET", roles + "/lookup", 403, token=tenant)
    check("POST", roles, 403, token=tenant, data=role_payload)
    check("GET", roles + "/lookup", 403, token=tenant,
          headers={"X-Tenant-Id": FOREIGN_ID})
    role_lookup = json_value(check("GET", roles + "/lookup", 200, token=admin))
    reserved_roles = [r for r in role_lookup
                      if r.get("title", "").casefold() == "superadmin"]
    assert len(reserved_roles) == 1, "Master System role lookup must return exactly one SuperAdmin"
    superadmin_role_id = str(uuid.UUID(reserved_roles[0]["id"]))

    permission_lookup = json_value(
        check("GET", perms + "/lookup?text=ROLES.CREATE", 200, token=admin))
    reserved_permissions = [p for p in permission_lookup
                            if p.get("code", "").upper() == "ROLES.CREATE"]
    assert len(reserved_permissions) == 1, "Reserved platform permission missing"
    reserved_permission_id = str(uuid.UUID(reserved_permissions[0]["id"]))

    # Forged caller target must be rejected, not silently rewritten or
    # mapped to HTTP 500. No untrusted tenant body can select Master storage.
    check("PUT", roles + "/" + FOREIGN_ID + "/permissions", 403,
          token=admin, data={"permissionIds": []})
    check("PUT", roles + "/" + superadmin_role_id + "/permissions", 403,
          token=admin, data={"permissionIds": []})
    check("DELETE", roles + "/" + superadmin_role_id, 403, token=admin)
    check("PUT", users + "/" + viewer_id + "/roles/" + superadmin_role_id,
          403, token=admin)
    check("PUT", users + "/" + viewer_id + "/permissions/" + reserved_permission_id + "/allow",
          403, token=admin)
    check("POST", perms, 403, token=admin,
          data={"code": "ROLES.CREATE", "name": "Forbidden catalog overwrite",
                "resourceId": FOREIGN_ID, "isActive": True,
                "permissionResources": []})

    role_id = str(uuid.UUID(json_value(check("POST", roles, 201,
                                             token=admin, data=role_payload))))
    stored = json_value(check("GET", roles + "/" + role_id, 200, token=admin))
    assert str(stored["id"]).lower() == role_id
    assert stored["name"] == role_payload["name"], "Created Role was not persisted"

    updated_name = "E2E HTTP Scoped Operator Updated"
    check("PUT", roles + "/" + role_id, 204, token=admin,
          data={"name": updated_name, "description": "Updated via HTTP",
                "isActive": True})
    updated = json_value(check("GET", roles + "/" + role_id, 200, token=admin))
    assert updated["name"] == updated_name, "Role update was not persisted"

    # Role Permission replacement is performed by real CQRS/EF and audited.
    check("PUT", roles + "/" + role_id + "/permissions", 204,
          token=admin, data={"permissionIds": [PERMISSION_ID]})

    role_link = users + "/" + viewer_id + "/roles/" + role_id
    check("PUT", role_link, 204, token=admin)
    check("PUT", role_link, 204, token=admin)  # No-op
    check("GET", roles + "/lookup", 403, token=viewer)  # Not SuperAdmin
    check("DELETE", role_link, 204, token=admin)
    check("DELETE", role_link, 204, token=admin)  # No-op
    check("PUT", users + "/" + tenant_id + "/roles/" + role_id, 403, token=admin)

    # Group role / membership grants and revocations with known Master fixture.
    group_role = groups + "/" + GROUP_ID + "/roles/" + role_id
    member = groups + "/" + GROUP_ID + "/members/" + viewer_id
    check("PUT", group_role, 204, token=admin)
    check("POST", groups + "/" + GROUP_ID + "/addmembers", 204,
          token=admin, data={"userIds": [viewer_id]})
    check("POST", groups + "/" + GROUP_ID + "/addmembers", 204,
          token=admin, data={"userIds": [viewer_id]})
    check("DELETE", member, 204, token=admin)
    check("DELETE", member, 204, token=admin)  # Idempotent revoke
    check("DELETE", group_role, 204, token=admin)
    check("DELETE", groups + "/" + GROUP_ID + "/members/" + tenant_id,
          403, token=admin)

    # Direct non-reserved permissions support Allow -> Deny -> Clear.
    override = users + "/" + viewer_id + "/permissions/" + PERMISSION_ID
    check("PUT", override + "/allow", 204, token=admin)
    check("PUT", override + "/allow", 204, token=admin)
    check("PUT", override + "/deny", 204, token=admin)
    check("DELETE", override, 204, token=admin)
    check("DELETE", override, 204, token=admin)

    # The privileged actor cannot modify their own grants via a normal API.
    check("PUT", users + "/" + admin_id + "/roles/" + role_id, 403, token=admin)

    # Finish actual platform Role CRUD after related grant links are removed.
    check("DELETE", roles + "/" + role_id, 204, token=admin)

    print(f"PASS: {PASSED} real HTTP status checks, plus persisted Role invariants", flush=True)


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
