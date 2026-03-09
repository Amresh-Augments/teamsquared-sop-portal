#!/usr/bin/env python3
"""SOP Portal Server — Static files + Supabase admin API proxy."""

import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

CONFIG_PATH = Path(__file__).parent / "config.json"
_config = {}
_supabase = None


def get_config():
    global _config
    if not _config:
        # Prefer environment variables (for Replit Secrets / production)
        url = os.environ.get("SUPABASE_URL")
        anon = os.environ.get("SUPABASE_ANON_KEY")
        service = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        if url and anon and service:
            _config = {
                "SUPABASE_URL": url,
                "SUPABASE_ANON_KEY": anon,
                "SUPABASE_SERVICE_ROLE_KEY": service,
            }
        else:
            # Fallback to config.json for local dev
            _config = json.loads(CONFIG_PATH.read_text())
    return _config


def get_supabase():
    global _supabase
    if _supabase is None:
        from supabase import create_client
        cfg = get_config()
        _supabase = create_client(cfg["SUPABASE_URL"], cfg["SUPABASE_SERVICE_ROLE_KEY"])
    return _supabase


class SOPHandler(SimpleHTTPRequestHandler):
    """Serves static files + admin API endpoints."""

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            self._handle_api_get(path)
        else:
            super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            self._handle_api_post(path)
        else:
            self._send_error(405, "Method not allowed")

    def do_PUT(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            self._handle_api_put(path)
        else:
            self._send_error(405, "Method not allowed")

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            self._handle_api_delete(path)
        else:
            self._send_error(405, "Method not allowed")

    # ----- API routing -----

    def _handle_api_get(self, path):
        if path == "/api/config":
            cfg = get_config()
            self._send_json({
                "SUPABASE_URL": cfg["SUPABASE_URL"],
                "SUPABASE_ANON_KEY": cfg["SUPABASE_ANON_KEY"],
            })
        elif path == "/api/me":
            user_id = self._verify_user()
            if not user_id:
                return
            self._get_my_sections(user_id)
        elif path == "/api/admin/users":
            admin = self._verify_admin()
            if not admin:
                return
            self._list_users()
        else:
            self._send_error(404, "Not found")

    def _handle_api_post(self, path):
        if path == "/api/admin/invite":
            admin = self._verify_admin()
            if not admin:
                return
            body = self._read_body()
            if body is None:
                return
            self._invite_user(body)
        else:
            self._send_error(404, "Not found")

    def _handle_api_put(self, path):
        if path.startswith("/api/admin/users/"):
            admin = self._verify_admin()
            if not admin:
                return
            user_id = path[len("/api/admin/users/"):]
            body = self._read_body()
            if body is None:
                return
            self._update_user(user_id, body)
        else:
            self._send_error(404, "Not found")

    def _handle_api_delete(self, path):
        if path.startswith("/api/admin/users/"):
            admin = self._verify_admin()
            if not admin:
                return
            user_id = path[len("/api/admin/users/"):]
            self._delete_user(user_id)
        else:
            self._send_error(404, "Not found")

    # ----- Auth verification -----

    def _verify_user(self):
        """Verify Bearer token. Returns user_id or None."""
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self._send_error(401, "Missing authorization token")
            return None

        token = auth_header[7:]
        sb = get_supabase()

        try:
            user_resp = sb.auth.get_user(token)
            return user_resp.user.id
        except Exception:
            self._send_error(401, "Invalid token")
            return None

    def _verify_admin(self):
        """Verify Bearer token and check is_admin. Returns user_id or None."""
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self._send_error(401, "Missing authorization token")
            return None

        token = auth_header[7:]
        sb = get_supabase()

        try:
            user_resp = sb.auth.get_user(token)
            user_id = user_resp.user.id
        except Exception:
            self._send_error(401, "Invalid token")
            return None

        try:
            profile = sb.table("profiles").select("is_admin").eq("id", user_id).single().execute()
            if not profile.data.get("is_admin"):
                self._send_error(403, "Admin access required")
                return None
        except Exception:
            self._send_error(403, "Profile not found")
            return None

        return user_id

    # ----- User endpoints -----

    def _get_my_sections(self, user_id):
        sb = get_supabase()
        try:
            result = sb.table("user_sections").select("section_id").eq("user_id", user_id).execute()
            section_ids = [row["section_id"] for row in (result.data or [])]
            self._send_json({"section_ids": section_ids})
        except Exception as e:
            self._send_error(500, str(e))

    # ----- Admin endpoints -----

    def _list_users(self):
        sb = get_supabase()
        try:
            profiles = sb.table("profiles").select("id, email, display_name, is_admin, created_at").order("created_at").execute()
            user_sections = sb.table("user_sections").select("user_id, section_id").execute()

            sections_map = {}
            for us in user_sections.data:
                uid = us["user_id"]
                if uid not in sections_map:
                    sections_map[uid] = []
                sections_map[uid].append(us["section_id"])

            result = []
            for p in profiles.data:
                p["section_ids"] = sections_map.get(p["id"], [])
                result.append(p)

            self._send_json(result)
        except Exception as e:
            self._send_error(500, str(e))

    def _invite_user(self, body):
        sb = get_supabase()
        email = body.get("email", "").strip()
        display_name = body.get("display_name", "").strip()
        is_admin = body.get("is_admin", False)
        section_ids = body.get("section_ids", [])

        if not email:
            self._send_error(400, "Email is required")
            return

        try:
            invite_resp = sb.auth.admin.invite_user_by_email(
                email,
                options={"data": {"display_name": display_name}}
            )
            user_id = invite_resp.user.id

            # Update profile (trigger may have created it)
            sb.table("profiles").upsert({
                "id": user_id,
                "email": email,
                "display_name": display_name,
                "is_admin": is_admin,
            }).execute()

            # Set section access
            if section_ids:
                rows = [{"user_id": user_id, "section_id": sid} for sid in section_ids]
                sb.table("user_sections").insert(rows).execute()

            self._send_json({"ok": True, "user_id": user_id})
        except Exception as e:
            self._send_error(500, str(e))

    def _update_user(self, user_id, body):
        sb = get_supabase()

        try:
            update_data = {}
            if "display_name" in body:
                update_data["display_name"] = body["display_name"]
            if "is_admin" in body:
                update_data["is_admin"] = body["is_admin"]

            if update_data:
                sb.table("profiles").update(update_data).eq("id", user_id).execute()

            if "section_ids" in body:
                # Replace all section assignments
                sb.table("user_sections").delete().eq("user_id", user_id).execute()
                section_ids = body["section_ids"]
                if section_ids:
                    rows = [{"user_id": user_id, "section_id": sid} for sid in section_ids]
                    sb.table("user_sections").insert(rows).execute()

            self._send_json({"ok": True})
        except Exception as e:
            self._send_error(500, str(e))

    def _delete_user(self, user_id):
        sb = get_supabase()

        try:
            sb.auth.admin.delete_user(user_id)
            self._send_json({"ok": True})
        except Exception as e:
            self._send_error(500, str(e))

    # ----- Helpers -----

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            return json.loads(raw)
        except (ValueError, json.JSONDecodeError) as e:
            self._send_error(400, f"Invalid JSON: {e}")
            return None

    def _send_json(self, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code, message):
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    os.chdir(Path(__file__).parent)

    port = int(os.environ.get("PORT", 5000))
    server = HTTPServer(("0.0.0.0", port), SOPHandler)
    print(f"SOP Portal server running on http://localhost:{port}")
    server.serve_forever()
