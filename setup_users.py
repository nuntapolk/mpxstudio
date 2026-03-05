#!/usr/bin/env python3
"""
MPX Studio — User Management CLI
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ใช้สำหรับจัดการ users ใน users.config.json

Usage:
  python setup_users.py list                        # ดูรายชื่อ users
  python setup_users.py add <username> <password>   # เพิ่ม user
  python setup_users.py passwd <username>           # เปลี่ยน password
  python setup_users.py disable <username>          # disable user
  python setup_users.py enable <username>           # enable user
  python setup_users.py delete <username>           # ลบ user
  python setup_users.py verify <username> <password># ตรวจสอบ password
  python setup_users.py gen-secret                  # สร้าง JWT secret ใหม่
"""

import sys, json, os, hashlib, base64, secrets, getpass

USERS_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.config.json")

MENU_KEYS = ["dashboard", "inventory", "mpx2", "insight", "vendor", "audit", "config"]
ROLE_PRESETS = {
    "admin":   {"roles": ["admin"],   "menus": ["*"]},
    "editor":  {"roles": ["editor"],  "menus": ["dashboard","inventory","mpx2","insight","vendor","audit"]},
    "viewer":  {"roles": ["viewer"],  "menus": ["dashboard","inventory","mpx2","insight","audit"]},
    "vendor":  {"roles": ["vendor"],  "menus": ["dashboard","vendor"]},
}

# ─── Hashing ──────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash password using PBKDF2-SHA256 (stdlib, no pip needed)"""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200000)
    return 'pbkdf2$sha256$200000$' + base64.b64encode(salt).decode() + '$' + base64.b64encode(dk).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against stored hash"""
    try:
        parts = hashed.split('$')
        if parts[0] == 'pbkdf2' and len(parts) == 5:
            _, algo, iterations, salt_b64, dk_b64 = parts
            salt = base64.b64decode(salt_b64)
            dk_stored = base64.b64decode(dk_b64)
            dk_check = hashlib.pbkdf2_hmac(algo.replace('sha', 'sha'), password.encode('utf-8'), salt, int(iterations))
            return dk_check == dk_stored
        return False
    except Exception:
        return False

# ─── Config I/O ───────────────────────────────────────────────────────────────

def load_config() -> dict:
    if not os.path.exists(USERS_CONFIG):
        print(f"❌ {USERS_CONFIG} not found. Creating empty config...")
        cfg = {"jwt_secret": secrets.token_hex(32), "token_expire_minutes": 480, "users": []}
        save_config(cfg)
        return cfg
    with open(USERS_CONFIG, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_config(cfg: dict):
    with open(USERS_CONFIG, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    print(f"✅ Saved to {USERS_CONFIG}")

def find_user(cfg: dict, username: str):
    for u in cfg.get("users", []):
        if u["username"] == username:
            return u
    return None

# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_list(cfg: dict):
    users = cfg.get("users", [])
    if not users:
        print("(no users)")
        return
    print(f"\n{'USERNAME':<14} {'DISPLAY NAME':<20} {'ROLES':<14} {'MENUS':<40} {'ACTIVE'}")
    print("-" * 100)
    for u in users:
        menus = ','.join(u.get('menus', []))
        roles = ','.join(u.get('roles', []))
        active = "✅" if u.get("active", True) else "❌"
        print(f"{u['username']:<14} {u.get('display_name',''):<20} {roles:<14} {menus:<40} {active}")
    print(f"\nTotal: {len(users)} user(s)")
    print(f"Token expire: {cfg.get('token_expire_minutes', 480)} minutes")

def cmd_add(cfg: dict, args: list):
    if len(args) < 2:
        print("Usage: python setup_users.py add <username> <password> [role_preset]")
        print(f"  Presets: {', '.join(ROLE_PRESETS.keys())}")
        return
    username = args[0]
    if find_user(cfg, username):
        print(f"❌ User '{username}' already exists")
        return

    password = args[1]
    preset_name = args[2] if len(args) > 2 else "viewer"
    preset = ROLE_PRESETS.get(preset_name, ROLE_PRESETS["viewer"])

    display_name = input(f"Display name [{username}]: ").strip() or username
    email = input(f"Email []: ").strip()

    user = {
        "username": username,
        "display_name": display_name,
        "email": email,
        "hashed_password": hash_password(password),
        "active": True,
        "roles": preset["roles"],
        "menus": preset["menus"],
    }
    cfg["users"].append(user)
    save_config(cfg)
    print(f"✅ User '{username}' added with role preset '{preset_name}'")

def cmd_passwd(cfg: dict, args: list):
    if not args:
        print("Usage: python setup_users.py passwd <username>")
        return
    username = args[0]
    user = find_user(cfg, username)
    if not user:
        print(f"❌ User '{username}' not found")
        return
    password = getpass.getpass(f"New password for {username}: ")
    if not password:
        print("❌ Password cannot be empty")
        return
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("❌ Passwords do not match")
        return
    user["hashed_password"] = hash_password(password)
    save_config(cfg)
    print(f"✅ Password updated for '{username}'")

def cmd_toggle(cfg: dict, username: str, active: bool):
    user = find_user(cfg, username)
    if not user:
        print(f"❌ User '{username}' not found")
        return
    user["active"] = active
    save_config(cfg)
    status = "enabled" if active else "disabled"
    print(f"✅ User '{username}' {status}")

def cmd_delete(cfg: dict, args: list):
    if not args:
        print("Usage: python setup_users.py delete <username>")
        return
    username = args[0]
    before = len(cfg["users"])
    cfg["users"] = [u for u in cfg["users"] if u["username"] != username]
    if len(cfg["users"]) == before:
        print(f"❌ User '{username}' not found")
        return
    confirm = input(f"Delete user '{username}'? (yes/no): ")
    if confirm.lower() != "yes":
        print("Cancelled.")
        return
    save_config(cfg)
    print(f"✅ User '{username}' deleted")

def cmd_verify(cfg: dict, args: list):
    if len(args) < 2:
        print("Usage: python setup_users.py verify <username> <password>")
        return
    username, password = args[0], args[1]
    user = find_user(cfg, username)
    if not user:
        print(f"❌ User '{username}' not found")
        return
    ok = verify_password(password, user["hashed_password"])
    print(f"{'✅ Password correct!' if ok else '❌ Password incorrect'}")

def cmd_gen_secret(cfg: dict):
    new_secret = secrets.token_hex(32)
    old = cfg.get("jwt_secret", "")
    print(f"Old secret: {old[:16]}...")
    print(f"New secret: {new_secret}")
    confirm = input("Replace jwt_secret in config? (yes/no): ")
    if confirm.lower() == "yes":
        cfg["jwt_secret"] = new_secret
        save_config(cfg)
        print("⚠️  All existing tokens are now invalid — users must re-login")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    cfg = load_config()
    cmd = args[0]
    rest = args[1:]

    if cmd == "list":           cmd_list(cfg)
    elif cmd == "add":          cmd_add(cfg, rest)
    elif cmd == "passwd":       cmd_passwd(cfg, rest)
    elif cmd == "disable":
        if rest: cmd_toggle(cfg, rest[0], False)
    elif cmd == "enable":
        if rest: cmd_toggle(cfg, rest[0], True)
    elif cmd == "delete":       cmd_delete(cfg, rest)
    elif cmd == "verify":       cmd_verify(cfg, rest)
    elif cmd == "gen-secret":   cmd_gen_secret(cfg)
    else:
        print(f"❌ Unknown command: {cmd}")
        print(__doc__)

if __name__ == "__main__":
    main()
