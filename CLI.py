from __future__ import annotations
import streamlit as st
import base64
from pathlib import Path

# ===========================
# Global page configuration
# ===========================
st.set_page_config(
    page_title="Amentum Scripting v2",
    layout="wide",
    page_icon="logo_1.png",
)

# ===========================
# Branding (clickable logo)
# ===========================
LOGO_PATH = "logo_1.png"
# Update this URL to your destination (SharePoint, intranet, company site, etc.)
LOGO_LINK = "https://www.amentum.com/"
st.logo(LOGO_PATH, size="large", link=LOGO_LINK)

@st.cache_data
def _img_to_base64(img_path: str) -> str:
    return base64.b64encode(Path(img_path).read_bytes()).decode("utf-8")

def render_top_banner():
    """Logo inside page body (highlighted header area)."""
    try:
        b64 = _img_to_base64(LOGO_PATH)
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:16px; margin: 0.25rem 0 1rem 0;">
              <a href="{LOGO_LINK}" target="_blank" rel="noopener noreferrer">
                <img src="data:image/png;base64,{b64}" style="height:52px;" />
              </a>
            </div>
            """,
            unsafe_allow_html=True,
        )
    except Exception:
        pass

# ===========================
# Manual Authentication (Supabase)
# ===========================
import bcrypt
from datetime import datetime, timezone

try:
    from supabase import create_client
except Exception:
    create_client = None

USER_TABLE = st.secrets.get("USER_TABLE", "app_users")

@st.cache_resource
def _supabase():
    if create_client is None:
        raise RuntimeError("Missing dependency: supabase. Add `supabase` to requirements.txt")
    url = st.secrets.get("SUPABASE_URL", "")
    key = st.secrets.get("SUPABASE_KEY", "")
    if not url or not key:
        raise RuntimeError("Missing SUPABASE_URL / SUPABASE_KEY in Streamlit secrets")
    return create_client(url, key)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception:
        return False

def db_get_user(username: str):
    sb = _supabase()
    res = sb.table(USER_TABLE).select("*").eq("username", username).limit(1).execute()
    data = getattr(res, "data", None) or []
    return data[0] if data else None

def db_user_exists(username: str) -> bool:
    return db_get_user(username) is not None

def db_create_user(username: str, role: str, created_by: str):
    sb = _supabase()
    payload = {
        "username": username,
        "role": role,
        "password_hash": None,
        "is_active": True,
        "created_at": _now_iso(),
        "created_by": created_by,
        "password_set_at": None,
    }
    sb.table(USER_TABLE).insert(payload).execute()

def db_set_password(username: str, password_hash: str):
    sb = _supabase()
    sb.table(USER_TABLE).update({"password_hash": password_hash, "password_set_at": _now_iso()}).eq("username", username).execute()

def db_list_users(limit: int = 200):
    sb = _supabase()
    res = sb.table(USER_TABLE).select("username,role,is_active,created_at,created_by,password_set_at").order("created_at", desc=True).limit(limit).execute()
    return getattr(res, "data", None) or []

def ensure_session_defaults():
    st.session_state.setdefault("auth_ok", False)
    st.session_state.setdefault("auth_user", "")
    st.session_state.setdefault("auth_role", "")

def bootstrap_admin_login():
    boot_user = st.secrets.get("ADMIN_BOOTSTRAP_USER", "")
    boot_pw = st.secrets.get("ADMIN_BOOTSTRAP_PASSWORD", "")
    if not boot_user or not boot_pw:
        return
    with st.expander("Admin bootstrap login", expanded=False):
        u = st.text_input("Bootstrap admin username", key="boot_user").strip()
        p = st.text_input("Bootstrap admin password", type="password", key="boot_pw")
        if st.button("Bootstrap login", key="boot_login_btn"):
            if u != boot_user or p != boot_pw:
                st.error("Invalid bootstrap credentials")
                return
            existing = db_get_user(boot_user)
            if not existing:
                db_create_user(boot_user, role="admin", created_by="bootstrap")
                db_set_password(boot_user, _hash_password(p))
            st.session_state.auth_ok = True
            st.session_state.auth_user = boot_user
            st.session_state.auth_role = "admin"
            st.success("Bootstrap admin login successful")
            st.rerun()

def login_flow():
    render_top_banner()
    st.title("Sign in")
    st.caption("Enter your username. If this is your first login (no password set yet), you will be prompted to create a password.")
    username = st.text_input("Username", key="login_username").strip()
    if not username:
        bootstrap_admin_login()
        return
    user = db_get_user(username)
    if not user:
        st.error("Invalid user")
        bootstrap_admin_login()
        return
    if not bool(user.get("is_active", True)):
        st.error("Your account is inactive. Please contact the admin.")
        bootstrap_admin_login()
        return
    stored = user.get("password_hash")
    if not stored:
        st.info("First login detected. Please create your password.")
        p1 = st.text_input("Create password", type="password", key="p1")
        p2 = st.text_input("Confirm password", type="password", key="p2")
        if st.button("Set password", key="set_pw_btn"):
            if len(p1) < 8:
                st.error("Password must be at least 8 characters.")
                return
            if p1 != p2:
                st.error("Passwords do not match.")
                return
            db_set_password(username, _hash_password(p1))
            st.success("Password saved. Please log in with your new password.")
            st.session_state.pop("p1", None)
            st.session_state.pop("p2", None)
            st.rerun()
        bootstrap_admin_login()
        return
    pw = st.text_input("Password", type="password", key="login_password")
    if st.button("Login", key="login_btn"):
        if _verify_password(pw, stored):
            st.session_state.auth_ok = True
            st.session_state.auth_user = username
            st.session_state.auth_role = user.get("role", "user") or "user"
            st.success("Login successful")
            st.rerun()
        else:
            st.error("Invalid password")
    bootstrap_admin_login()

def require_auth_gate():
    ensure_session_defaults()
    if not st.session_state.get("auth_ok", False):
        login_flow()
        st.stop()

def logout_button():
    if st.sidebar.button("Logout", key="logout_btn"):
        st.session_state.auth_ok = False
        st.session_state.auth_user = ""
        st.session_state.auth_role = ""
        st.rerun()

def admin_panel():
    render_top_banner()
    st.title("Admin")
    st.caption("Create usernames. New users will set their password on first login.")
    with st.expander("Create new user", expanded=True):
        new_user = st.text_input("New username", key="admin_new_user").strip()
        new_role = st.selectbox("Role", ["user", "admin"], index=0, key="admin_new_role")
        if st.button("Create user", key="admin_create_btn"):
            if not new_user:
                st.error("Username cannot be empty")
            elif db_user_exists(new_user):
                st.warning("User already exists")
            else:
                db_create_user(new_user, new_role, created_by=st.session_state.get("auth_user", "admin"))
                st.success(f"User {new_user} created")
                st.rerun()
    st.subheader("Users")
    try:
        import pandas as pd
        st.dataframe(pd.DataFrame(db_list_users()), use_container_width=True)
    except Exception:
        st.write(db_list_users())

# ---------------------------
# RADIO CLI APP (merged from v6.py)
# ---------------------------

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd
import streamlit as st

# Optional native folder picker (best when running locally)
try:
    import tkinter as tk
    from tkinter import filedialog
except Exception:
    tk = None
    filedialog = None

# ======================================
# RADIO LIBRARY / CAPABILITY DEFINITIONS
# ======================================
PORT_PATTERN_ACBD = ["A", "C", "B", "D"]
PORT_PATTERN_AB = ["A", "B"]
PORT_PATTERN_ACBDEGFH = ["A", "C", "B", "D", "E", "G", "F", "H"]


def make_tx_ports(*ports: str) -> Set[str]:
    return {p.upper() for p in ports}


def _modes_4port_acbd() -> Dict[str, Dict]:
    # 4-port radios where 2T2R can be AB or CD.
    return {
        "4T4R": {"rx": 4, "tx": 4, "active_ports": set(["A", "B", "C", "D"])},
        "2T2R_AB": {"rx": 2, "tx": 2, "active_ports": set(["A", "B"])},
        "2T2R_CD": {"rx": 2, "tx": 2, "active_ports": set(["C", "D"])},
    }


def _allowed_modes_4port() -> List[str]:
    return ["2T2R_AB", "2T2R_CD", "4T4R"]


def _modes_b29_2t0r_ab_only() -> Dict[str, Dict]:
    # Band 29 is DL-only; model as TX-only.
    return {"2T0R_AB": {"rx": 0, "tx": 2, "active_ports": set(["A", "B"])}}


def _modes_b29_4port_2t0r_ab_or_cd() -> Dict[str, Dict]:
    return {
        "2T0R_AB": {"rx": 0, "tx": 2, "active_ports": set(["A", "B"])},
        "2T0R_CD": {"rx": 0, "tx": 2, "active_ports": set(["C", "D"])},
    }

def render_nr_sector_carrier(site: str, sector: SectorConfig, p: BWEParams) -> List[str]:
    """
    NR equivalent of render_sector_carrier.
    Creates two 'set' blocks on GNBDUFunction=1,NRSectorCarrier=<SectorCarrierId>.
    First clears values to <empty>, second sets RX/TX counts and branch references.
    """
    mo_fdn = fdn(
        "SubNetwork=ONRM_ROOT_MO",
        f"MeContext={site}",
        me(site),
        "GNBDUFunction=1",
        f"NRSectorCarrier={p.sector_carrier_id}",
    )

    eff_mode = p.mode_override or sector.radio_mode
    entry_rx, entry_tx = rx_tx_for(sector.radio_model, eff_mode)

    rx_list = [] if entry_rx == 0 else rx_branches_for_entry(sector, p)
    rx_refs = [
        fdn(
            "SubNetwork=ONRM_ROOT_MO",
            f"MeContext={site}",
            me(site),
            "Equipment=1",
            f"AntennaUnitGroup={sector.aug_group}",
            f"RfBranch={b}",
        )
        for b in rx_list
    ]

    tx_list = [] if entry_tx == 0 else tx_branches_for_entry(sector, p)
    tx_refs = [
        fdn(
            "SubNetwork=ONRM_ROOT_MO",
            f"MeContext={site}",
            me(site),
            "Equipment=1",
            f"AntennaUnitGroup={sector.aug_group}",
            f"RfBranch={b}",
        )
        for b in tx_list
    ]

    empty_params = {
        "noOfRxAntennas": "<empty>",
        "noOfTxAntennas": "<empty>",
    }

    full_params = {
        "noOfRxAntennas": f"\"{entry_rx}\"",
        "noOfTxAntennas": f"\"{entry_tx}\"",
        "rfBranchRxRef": "<empty>" if entry_rx == 0 else "[" + ",".join([f"\"{r}\"" for r in rx_refs]) + "]",
        "rfBranchTxRef": "<empty>" if entry_tx == 0 else "[" + ",".join([f"\"{r}\"" for r in tx_refs]) + "]",
    }

    return [
        render_block("set", mo_fdn, empty_params),
        render_block("set", mo_fdn, full_params),
    ]
    
RADIO_LIBRARY: Dict[str, Dict] = {
    # Single-band / multi-band (single RU)
    "4478": {
        "display": "4478 (L700/F-NET/850; 2T2R AB/CD or 4T4R ACBD)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["L700", "F-NET", "850"],
        "tx_ports_by_band": {"L700": make_tx_ports("A", "B", "C", "D"), "F-NET": make_tx_ports("A", "B", "C", "D"), "850": make_tx_ports("A", "B", "C", "D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"L700": ["4T4R"], "F-NET": _allowed_modes_4port(), "850": _allowed_modes_4port()},
    },
    "RRUE2": {
        "display": "RRUE2 (B29 SDL DL-only; 2T0R AB)",
        "ports": ["A", "B"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_AB,
        "modes": _modes_b29_2t0r_ab_only(),
        "bands": ["B29"],
        "tx_ports_by_band": {"B29": make_tx_ports("A", "B")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"B29": ["2T0R_AB"]},
    },
    "2012": {
        "display": "2012 (B29 SDL DL-only; 2T0R AB)",
        "ports": ["A", "B"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_AB,
        "modes": _modes_b29_2t0r_ab_only(),
        "bands": ["B29"],
        "tx_ports_by_band": {"B29": make_tx_ports("A", "B")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"B29": ["2T0R_AB"]},
    },
    "2203": {
        "display": "2203 (F-NET/850/PCS/AWS-B66; 2T2R AB)",
        "ports": ["A", "B"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_AB,
        "modes": {"2T2R_AB": {"rx": 2, "tx": 2, "active_ports": set(["A", "B"])}} ,
        "bands": ["F-NET", "850", "PCS", "AWS/B66"],
        "tx_ports_by_band": {"F-NET": make_tx_ports("A", "B"), "850": make_tx_ports("A", "B"), "PCS": make_tx_ports("A", "B"), "AWS/B66": make_tx_ports("A", "B")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"F-NET": ["2T2R_AB"], "850": ["2T2R_AB"], "PCS": ["2T2R_AB"], "AWS/B66": ["2T2R_AB"]},
    },
    "RRU32": {
        "display": "RRU32 (PCS/AWS-B66/WCS; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["PCS", "AWS/B66", "WCS"],
        "tx_ports_by_band": {"PCS": make_tx_ports("A", "B", "C", "D"), "AWS/B66": make_tx_ports("A", "B", "C", "D"), "WCS": make_tx_ports("A", "B", "C", "D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"PCS": _allowed_modes_4port(), "AWS/B66": _allowed_modes_4port(), "WCS": _allowed_modes_4port()},
    },
    "4415": {
        "display": "4415 (PCS/WCS; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["PCS", "WCS"],
        "tx_ports_by_band": {"PCS": make_tx_ports("A", "B", "C", "D"), "WCS": make_tx_ports("A", "B", "C", "D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"PCS": _allowed_modes_4port(), "WCS": _allowed_modes_4port()},
    },
    "4402": {
        "display": "4402 (PCS/AWS-B66; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["PCS", "AWS/B66"],
        "tx_ports_by_band": {"PCS": make_tx_ports("A", "B", "C", "D"), "AWS/B66": make_tx_ports("A", "B", "C", "D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"PCS": _allowed_modes_4port(), "AWS/B66": _allowed_modes_4port()},
    },
    "4426": {
        "display": "4426 (AWS-B66; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["AWS/B66"],
        "tx_ports_by_band": {"AWS/B66": make_tx_ports("A", "B", "C", "D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"AWS/B66": _allowed_modes_4port()},
    },
    "4471": {
        "display": "4471 (WCS; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["WCS"],
        "tx_ports_by_band": {"WCS": make_tx_ports("A", "B", "C", "D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"WCS": _allowed_modes_4port()},
    },
    "4435": {
        "display": "4435 (C-Band; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["C-Band"],
        "tx_ports_by_band": {"C-Band": make_tx_ports("A", "B", "C", "D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"C-Band": _allowed_modes_4port()},
    },
    "4408": {
        "display": "4408 (DoD; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["DoD"],
        "tx_ports_by_band": {"DoD": make_tx_ports("A", "B", "C", "D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"DoD": _allowed_modes_4port()},
    },

    # Dual-band radios (4 ports)
    "4449": {
        "display": "4449 (L700+850; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["L700", "850"],
        "tx_ports_by_band": {"L700": make_tx_ports("A","B","C","D"), "850": make_tx_ports("A","B","C","D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"L700": _allowed_modes_4port(), "850": _allowed_modes_4port()},
    },
    "4490": {
        "display": "4490 (L700+850; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["L700", "850"],
        "tx_ports_by_band": {"L700": make_tx_ports("A","B","C","D"), "850": make_tx_ports("A","B","C","D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"L700": _allowed_modes_4port(), "850": _allowed_modes_4port()},
    },
    "4467": {
        "display": "4467 (C-Band+DoD; 2T2R AB/CD or 4T4R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": _modes_4port_acbd(),
        "bands": ["C-Band", "DoD"],
        "tx_ports_by_band": {"C-Band": make_tx_ports("A","B","C","D"), "DoD": make_tx_ports("A","B","C","D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"C-Band": _allowed_modes_4port(), "DoD": _allowed_modes_4port()},
    },
    "4494": {
        "display": "4494 (F-NET + B29; per-band mode allowed: F-NET=2T2R/4T4R, B29=2T0R)",
        "ports": ["A", "B", "C", "D"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBD,
        "modes": {**_modes_4port_acbd(), **_modes_b29_4port_2t0r_ab_or_cd()},
        "bands": ["F-NET", "B29"],
        "tx_ports_by_band": {"F-NET": make_tx_ports("A","B","C","D"), "B29": make_tx_ports("A","B","C","D")},
        "preferred_band_by_port": {},
        "allowed_modes_by_band": {"F-NET": _allowed_modes_4port(), "B29": ["2T0R_AB", "2T0R_CD"]},
        "allow_per_band_mode": True,
    },

    # Dual-band 8-port radios with PCS/AWS split
    "8843": {
        "display": "8843 (PCS=A-D, AWS/B66=E-H; 2T2R AB+EF or CD+GH; 4T4R)",
        "ports": ["A","B","C","D","E","F","G","H"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_ACBDEGFH,
        "modes": {
            "2T2R_ABEF": {"rx": 2, "tx": 2, "active_ports": set(["A","B","E","F"])},
            "2T2R_CDGH": {"rx": 2, "tx": 2, "active_ports": set(["C","D","G","H"])},
            "4T4R": {"rx": 4, "tx": 4, "active_ports": set(["A","B","C","D","E","F","G","H"])},
        },
        "bands": ["PCS", "AWS/B66"],
        "tx_ports_by_band": {"PCS": make_tx_ports("A","B","C","D"), "AWS/B66": make_tx_ports("E","F","G","H")},
        "preferred_band_by_port": {"A": "PCS", "B": "PCS", "C": "PCS", "D": "PCS", "E": "AWS/B66", "F": "AWS/B66", "G": "AWS/B66", "H": "AWS/B66"},
        "allowed_modes_by_band": {"PCS": ["2T2R_ABEF","2T2R_CDGH","4T4R"], "AWS/B66": ["2T2R_ABEF","2T2R_CDGH","4T4R"]},
    },
    "4890": {
        "display": "4890 (PCS=A-D, AWS/B66=E-H; 2T2R AB+EF or CD+GH; 4T4R; 8Rx4Tx)",
        "ports": ["A","B","C","D","E","F","G","H"],
        "default_rfport": "R",
        "port_pattern": PORT_PATTERN_ACBDEGFH,
        "modes": {
            "2T2R_ABEF": {"rx": 2, "tx": 2, "active_ports": set(["A","B","E","F"])},
            "2T2R_CDGH": {"rx": 2, "tx": 2, "active_ports": set(["C","D","G","H"])},
            "4T4R": {"rx": 4, "tx": 4, "active_ports": set(["A","B","C","D","E","F","G","H"])},
            "8Rx4Tx": {"rx": 8, "tx": 4, "active_ports": set(["A","B","C","D","E","F","G","H"])},
        },
        "bands": ["PCS", "AWS/B66"],
        "tx_ports_by_band": {"PCS": make_tx_ports("A","B","C","D"), "AWS/B66": make_tx_ports("E","F","G","H")},
        "preferred_band_by_port": {"A": "PCS", "B": "PCS", "C": "PCS", "D": "PCS", "E": "AWS/B66", "F": "AWS/B66", "G": "AWS/B66", "H": "AWS/B66"},
        "allowed_modes_by_band": {"PCS": ["2T2R_ABEF","2T2R_CDGH","4T4R","8Rx4Tx"], "AWS/B66": ["2T2R_ABEF","2T2R_CDGH","4T4R","8Rx4Tx"]},
    },

    # 4460: two 2203 combined; AB only; dual-sub RRU
    "4460": {
        "display": "4460 (two 2203 combined; PCS/AWS-B66; 2T2R AB only; dual-sub RRU)",
        "ports": ["A", "B"],
        "default_rfport": None,
        "port_pattern": PORT_PATTERN_AB,
        "modes": {"2T2R_AB": {"rx": 2, "tx": 2, "active_ports": set(["A", "B"])}} ,
        "bands": ["PCS", "AWS/B66"],
        "tx_ports_by_band": {"PCS": make_tx_ports("A", "B"), "AWS/B66": make_tx_ports("A", "B")},
        "preferred_band_by_port": {},
        "dual_sub_rru": True,
        "sub_rru_suffix_by_band": {"PCS": "1", "AWS/B66": "2"},
        "allowed_modes_by_band": {"PCS": ["2T2R_AB"], "AWS/B66": ["2T2R_AB"]},
    },
}

# ============================
# Generic helpers
# ============================

def active_ports(model: str, mode: str) -> Set[str]:
    return set(RADIO_LIBRARY[model]["modes"][mode]["active_ports"])


def port_pattern(model: str) -> List[str]:
    return RADIO_LIBRARY[model]["port_pattern"]


def rx_tx_for(model: str, mode: str) -> Tuple[int, int]:
    md = RADIO_LIBRARY[model]["modes"][mode]
    return int(md["rx"]), int(md["tx"])


def parse_int_list(raw: str) -> Optional[List[int]]:
    raw = (raw or "").strip()
    if raw == "":
        return []
    parts = [p.strip() for p in raw.replace(" ", ",").split(",") if p.strip()]
    out: List[int] = []
    for p in parts:
        try:
            out.append(int(p))
        except ValueError:
            return None
    return out


def parse_branch_spec(spec: str) -> Optional[List[int]]:
    if spec is None:
        return []
    s = spec.strip()
    if s == "":
        return []
    nums: List[int] = []
    parts = [p.strip() for p in s.split(",") if p.strip()]
    for part in parts:
        tokens = [t.strip() for t in part.replace(" ", ",").split(",") if t.strip()]
        for token in tokens:
            if "-" in token:
                a, b = [x.strip() for x in token.split("-", 1)]
                try:
                    start = int(a)
                    end = int(b)
                except ValueError:
                    return None
                step = 1 if start <= end else -1
                nums.extend(list(range(start, end + step, step)))
            else:
                try:
                    nums.append(int(token))
                except ValueError:
                    return None
    return sorted(set(nums))


def auto_map_for_sector(model: str, mode: str, branches: List[int]) -> Dict[int, str]:
    if branches is None:
        return {}
    uniq_branches = sorted(set(branches))
    if len(uniq_branches) == 0:
        return {}
    act = active_ports(model, mode)
    pattern = port_pattern(model)
    ordered_ports = [p for p in pattern if p in act]
    if len(uniq_branches) > len(ordered_ports):
        return {}
    return {b: p for b, p in zip(uniq_branches, ordered_ports)}


# ============================
# Data model
# ============================

@dataclass
class RiLinkConfig:
    link_number: str
    ri_port_ref1: str
    ri_port_ref2: str
    site: str


@dataclass
class BWEParams:
    band: str
    tech: str  # LTE or NR or AUTO
    bwe_index: int
    sector_equipment_number: str
    sector_carrier_id: str
    configured_power: str
    attenuation: str
    delay: str
    antenna_unit: str
    antenna_subunit: str
    rfbs: List[int]
    site: str
    mode_override: Optional[str]


@dataclass
class SectorConfig:
    sector_number: int
    aug_group: str
    rru_base: str
    radio_model: str
    radio_mode: str
    shared_sector_equipment: bool
    params: List[BWEParams]
    rilinks: List[RiLinkConfig]
    branch_port_map: Dict[int, str]
    radio_site: str
    create_in_both_sites: bool


@dataclass
class WizardConfig:
    created_at: str
    sitename: str
    sitename2: Optional[str]
    sectors: List[SectorConfig]
    vswr_enable: bool
    vswr_ports: List[str]
    vswr_sensitivity: str

    site_tech: Dict[str, str]
# ============================
# FDN helpers
# ============================

def me(site: str) -> str:
    return f"ManagedElement={site}"


def fdn(*parts: str) -> str:
    return ",".join(parts)


def render_block(action: str, fdn_value: str, params: Dict[str, str]) -> str:
    lines = [action, f"FDN : {fdn_value}"]
    for k, v in params.items():
        lines.append(f"{k} : {v}")
    return "\n".join(lines)


def replicate_15(value: str) -> str:
    return "[" + ", ".join([value] * 15) + "]"

# ============================
# Branch/Port helpers
# ============================

def rfport_for_branch(sector: SectorConfig, branch: int) -> str:
    if branch not in sector.branch_port_map:
        raise KeyError(f"No Branch→Port mapping for sector {sector.sector_number}, branch {branch}")
    return sector.branch_port_map[branch]


def sort_branches_by_port(sector: SectorConfig, branches: List[int], effective_mode: Optional[str] = None) -> List[int]:
    pat = port_pattern(sector.radio_model)
    rank = {p: i for i, p in enumerate(pat)}
    if effective_mode:
        act = active_ports(sector.radio_model, effective_mode)
        branches = [b for b in branches if rfport_for_branch(sector, b) in act]
    return sorted(branches, key=lambda b: (rank.get(rfport_for_branch(sector, b), 999), b))


def tx_branches_for_entry(sector: SectorConfig, p: BWEParams) -> List[int]:
    eff_mode = p.mode_override or sector.radio_mode
    entry_rx, entry_tx = rx_tx_for(sector.radio_model, eff_mode)
    if entry_tx == 0:
        return []
    tx_ports = set(RADIO_LIBRARY[sector.radio_model]["tx_ports_by_band"].get(p.band, set()))
    act = active_ports(sector.radio_model, eff_mode)
    allowed_ports = {x for x in tx_ports if x in act}
    if not allowed_ports:
        return []
    tx = [b for b in p.rfbs if rfport_for_branch(sector, b) in allowed_ports]
    return sort_branches_by_port(sector, tx, effective_mode=eff_mode)


def rx_branches_for_entry(sector: SectorConfig, p: BWEParams) -> List[int]:
    """Compute RX branches for a carrier.

    For ANY mode with RX > TX (e.g., 8Rx4Tx), if the carrier RFBranches list has fewer than RX,
    we expand RX using the radio mapping and take up to RX branches.

    If RFBranches already contains >= RX, we honor it.
    """
    eff_mode = p.mode_override or sector.radio_mode
    entry_rx, entry_tx = rx_tx_for(sector.radio_model, eff_mode)
    if entry_rx == 0:
        return []

    user = sorted(set(p.rfbs))
    if len(user) >= entry_rx:
        return sort_branches_by_port(sector, user, effective_mode=eff_mode)

    # Only expand when RX > TX
    if entry_rx <= entry_tx:
        return sort_branches_by_port(sector, user, effective_mode=eff_mode)

    all_mapped = sorted(set(sector.branch_port_map.keys()))
    ordered = sort_branches_by_port(sector, all_mapped, effective_mode=eff_mode)
    return ordered[:entry_rx] if len(ordered) >= entry_rx else ordered


def preferred_rru_for_band(sector: SectorConfig, band: str) -> str:
    md = RADIO_LIBRARY[sector.radio_model]
    if md.get("dual_sub_rru"):
        suf = md.get("sub_rru_suffix_by_band", {}).get(band)
        if suf:
            return f"{sector.rru_base}{suf}"
    return sector.rru_base


def params_visible_for_site(sector: SectorConfig, site: str) -> List[BWEParams]:
    """Params used to build antenna objects (AUs/AuPorts/RfBranches) in a given site.

    If the radio is created in both sites, include ALL params (from both sites) so both nodes
    get a complete set of branches/ports.

    Otherwise, include only params belonging to that site.
    """
    if sector.create_in_both_sites:
        return sector.params
    return [p for p in sector.params if p.site == site]


def unique_rrus_for_site(cfg: WizardConfig, site: str) -> List[Tuple[str, str, bool]]:
    """Return list of (rru_number, model_for_ports, shared_external) for this site."""
    rr: Dict[str, Tuple[str, bool]] = {}
    for s in cfg.sectors:
        md = RADIO_LIBRARY[s.radio_model]

        # Determine if this sector's RRUs should exist in this site
        in_this_site = any(p.site == site for p in s.params)
        create_here = in_this_site or s.create_in_both_sites
        if not create_here:
            continue

        shared_flag = bool(s.create_in_both_sites)

        if md.get("dual_sub_rru"):
            # only create the sub RRUs actually used by bands present (across visible params for this site)
            used_params = params_visible_for_site(s, site)
            used_rrus = {preferred_rru_for_band(s, p.band) for p in used_params}
            for rru in used_rrus:
                # mark shared if any sector marks it shared
                if rru not in rr:
                    rr[rru] = (s.radio_model, shared_flag)
                else:
                    rr[rru] = (rr[rru][0], rr[rru][1] or shared_flag)
        else:
            if s.rru_base not in rr:
                rr[s.rru_base] = (s.radio_model, shared_flag)
            else:
                rr[s.rru_base] = (rr[s.rru_base][0], rr[s.rru_base][1] or shared_flag)

    return sorted([(k, v[0], v[1]) for k, v in rr.items()], key=lambda x: x[0])


def band_preference_for_port(model: str, port_letter: str) -> Optional[str]:
    return RADIO_LIBRARY[model].get("preferred_band_by_port", {}).get(port_letter)

# ============================
# ENM blocks
# ============================

def render_rru(site: str, rru: str, shared_external: bool) -> str:
    mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"FieldReplaceableUnit=RRU-{rru}")
    params = {
        "administrativeState": "UNLOCKED",
        "fieldReplaceableUnitId": f'"RRU-{rru}"',
        "isSharedWithExternalMe": "TRUE" if shared_external else "FALSE",
    }
    return render_block("create", mo_fdn, params)


def render_rfports(site: str, model: str, rru: str) -> List[str]:
    md = RADIO_LIBRARY[model]
    ports = md["ports"]
    default_rfport = md.get("default_rfport")

    def rfport_create(port_name: str, vswr_active: bool, vswr_sens: str) -> str:
        mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"FieldReplaceableUnit=RRU-{rru}", f"RfPort={port_name}")
        params = {
            "administrativeState": "UNLOCKED",
            "antennaSupervisionActive": "false",
            "automaticANUrecovery": "true",
            "pimdAlarmActive": "false",
            "pimdMeasDuration": "LONG",
            "pimdThreshold": "300",
            "rfPortId": f'"{port_name}"',
            "userLabel": "<empty>",
            "vswrSupervisionActive": "true" if vswr_active else "false",
            "vswrSupervisionSensitivity": vswr_sens,
        }
        return render_block("create", mo_fdn, params)

    blocks: List[str] = []
    if default_rfport:
        blocks.append(rfport_create(default_rfport, vswr_active=False, vswr_sens='"-1"'))
    for p in ports:
        blocks.append(rfport_create(p, vswr_active=True, vswr_sens="70"))
    return blocks


def render_riports(site: str, rru: str) -> List[str]:
    blocks: List[str] = []
    for p in ("DATA_1", "DATA_2"):
        mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"FieldReplaceableUnit=RRU-{rru}", f"RiPort={p}")
        blocks.append(render_block("create", mo_fdn, {"administrativeState": "UNLOCKED", "riPortId": p}))
    return blocks


def render_alarmports(site: str, rru: str) -> List[str]:
    blocks: List[str] = []
    for i in (1, 2):
        mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"FieldReplaceableUnit=RRU-{rru}", f"AlarmPort={i}")
        params = {
            "administrativeState": "LOCKED",
            "alarmPortId": str(i),
            "alarmSlogan": "<empty>",
            "filterAlgorithm": "AUTO",
            "filterDelay": "60",
            "filterTime": "0",
            "normallyOpen": "false",
            "perceivedSeverity": "MAJOR",
            "userLabel": "<empty>",
        }
        blocks.append(render_block("create", mo_fdn, params))
    return blocks


def render_vswr(site: str, rru: str, sensitivity: str, ports: List[str]) -> List[str]:
    blocks: List[str] = []
    for port in ports:
        for fbd in (1, 2):
            mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"FieldReplaceableUnit=RRU-{rru}", f"RfPort={port}", f"FreqBandData={fbd}")
            blocks.append(render_block("set", mo_fdn, {"vswrSupervisionActive": "true", "vswrSupervisionSensitivity": sensitivity}))
    return blocks


def render_rilinks(site: str, sector: SectorConfig) -> List[str]:
    blocks: List[str] = []
    for link in sector.rilinks:
        if link.site != site:
            continue
        mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"RiLink={link.link_number}")
        params = {"riLinkId": str(link.link_number), "riPortRef1": f'"{link.ri_port_ref1}"', "riPortRef2": f'"{link.ri_port_ref2}"'}
        blocks.append(render_block("create", mo_fdn, params))
    return blocks


def render_sector_equipment_function(site: str, sector: SectorConfig, p: BWEParams) -> str:
    mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "NodeSupport=1", f"SectorEquipmentFunction={p.sector_equipment_number}")

    # Use RX branch list (expanded for RX>TX modes)
    rf_list = rx_branches_for_entry(sector, p)
    rf_refs = [fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"AntennaUnitGroup={sector.aug_group}", f"RfBranch={b}") for b in rf_list]

    return render_block("set", mo_fdn, {"rfBranchRef": "[" + ",".join([f'\"{r}\"' for r in rf_refs]) + "]"})


def render_sector_carrier(site: str, sector: SectorConfig, p: BWEParams) -> List[str]:
    mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "ENodeBFunction=1", f"SectorCarrier={p.sector_carrier_id}")

    eff_mode = p.mode_override or sector.radio_mode
    entry_rx, entry_tx = rx_tx_for(sector.radio_model, eff_mode)

    rx_list = [] if entry_rx == 0 else rx_branches_for_entry(sector, p)
    rx_refs = [fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"AntennaUnitGroup={sector.aug_group}", f"RfBranch={b}") for b in rx_list]

    tx_list = [] if entry_tx == 0 else tx_branches_for_entry(sector, p)
    tx_refs = [fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"AntennaUnitGroup={sector.aug_group}", f"RfBranch={b}") for b in tx_list]

    empty_params = {"rfBranchRxRef": "<empty>", "rfBranchTxRef": "<empty>", "noOfRxAntennas": f'"{entry_rx}"', "noOfTxAntennas": f'"{entry_tx}"'}
    full_params = {
        "rfBranchRxRef": "<empty>" if entry_rx == 0 else "[" + ",".join([f'\"{r}\"' for r in rx_refs]) + "]",
        "rfBranchTxRef": "<empty>" if entry_tx == 0 else "[" + ",".join([f'\"{r}\"' for r in tx_refs]) + "]",
        "configuredMaxTxPower": f'"{p.configured_power}"',
        "noOfRxAntennas": f'"{entry_rx}"',
        "noOfTxAntennas": f'"{entry_tx}"',
    }
    return [render_block("set", mo_fdn, empty_params), render_block("set", mo_fdn, full_params)]

# ============================
# Table editors (dtype-safe)
# ============================

ALL_MODES = sorted({m for r in RADIO_LIBRARY.values() for m in r["modes"].keys()})
ALL_BANDS = sorted({b for r in RADIO_LIBRARY.values() for b in r.get("bands", [])})
def _empty_radios_df(n_rows: int, site_choices: List[str]) -> pd.DataFrame:
    first_model = sorted(RADIO_LIBRARY.keys())[0]
    first_mode = list(RADIO_LIBRARY[first_model]["modes"].keys())[0]
    default_site = site_choices[0] if site_choices else ""
    return pd.DataFrame({
        "Radio": pd.Series([f"R{i+1}" for i in range(n_rows)], dtype="string"),
        "RadioSite": pd.Series([default_site] * n_rows, dtype="string"),
        "RadioModel": pd.Series([first_model] * n_rows, dtype="string"),
        "RadioMode": pd.Series([first_mode] * n_rows, dtype="string"),
        "RRUBase": pd.Series([""] * n_rows, dtype="string"),
        "CreateInBothSites": pd.Series([False] * n_rows, dtype="bool"),
        "SharedSE": pd.Series([False] * n_rows, dtype="bool"),
        "SharedSENumber": pd.Series([""] * n_rows, dtype="string"),
    })


def radios_table(ag_key: str, n_rows: int, site_choices: List[str]) -> pd.DataFrame:
    """Radios table wrapped in a form to prevent Streamlit data_editor 'type twice' behavior.

    Values are committed only when the user clicks 'Apply radios table'.
    """
    ss_key = f"radios_df_{ag_key}"
    if ss_key not in st.session_state:
        st.session_state[ss_key] = _empty_radios_df(n_rows, site_choices)

    df = st.session_state[ss_key]

    # Resize
    if len(df) != n_rows:
        if len(df) > n_rows:
            df = df.iloc[:n_rows].copy()
        else:
            add_n = n_rows - len(df)
            add_df = _empty_radios_df(add_n, site_choices)
            add_df["Radio"] = pd.Series([f"R{i+1}" for i in range(len(df), n_rows)], dtype="string")
            df = pd.concat([df, add_df], ignore_index=True)
        st.session_state[ss_key] = df
        df = st.session_state[ss_key]

    # Dtypes
    for c in ["Radio", "RadioSite", "RadioModel", "RadioMode", "RRUBase", "SharedSENumber"]:
        df[c] = df[c].astype("string").fillna("")
    for c in ["CreateInBothSites", "SharedSE"]:
        df[c] = df[c].astype("bool").fillna(False)

    model_options = sorted(RADIO_LIBRARY.keys())

    with st.form(key=f"radios_form_{ag_key}"):
        edited = st.data_editor(
            df,
            key=f"radios_editor_{ag_key}",
            num_rows="fixed",
            use_container_width=True,
            hide_index=True,
            column_config={
                "Radio": st.column_config.TextColumn("Radio", required=True),
                "RadioSite": st.column_config.SelectboxColumn("Site", options=site_choices, required=True),
                "RadioModel": st.column_config.SelectboxColumn("Model", options=model_options, required=True),
                "RadioMode": st.column_config.SelectboxColumn("Mode", options=ALL_MODES, required=True),
                "RRUBase": st.column_config.TextColumn("RRU Base", required=True),
                "CreateInBothSites": st.column_config.CheckboxColumn("Create in both sites?"),
                "SharedSE": st.column_config.CheckboxColumn("Shared SE?"),
                "SharedSENumber": st.column_config.TextColumn("Shared SE Number"),
            },
        )
        applied = st.form_submit_button("Apply radios table")

    if applied:
        fixed = edited.copy()
        auto_fixed = False
        for i, row in fixed.iterrows():
            model = str(row["RadioModel"])
            valid_modes = list(RADIO_LIBRARY[model]["modes"].keys())
            if str(row["RadioMode"]) not in valid_modes:
                fixed.at[i, "RadioMode"] = valid_modes[0]
                auto_fixed = True

        if auto_fixed:
            st.info("Some Mode values were invalid for the selected model and were auto-corrected.")

        # stabilize types
        for c in ["Radio", "RadioSite", "RadioModel", "RadioMode", "RRUBase", "SharedSENumber"]:
            fixed[c] = fixed[c].astype("string").fillna("")
        for c in ["CreateInBothSites", "SharedSE"]:
            fixed[c] = fixed[c].astype("bool").fillna(False)

        st.session_state[ss_key] = fixed
        return fixed

    return st.session_state[ss_key]


def _empty_map_df() -> pd.DataFrame:
    return pd.DataFrame({"Branch": pd.Series(dtype="Int64"), "Port": pd.Series(dtype="string")})


def _set_mapping_df_from_dict(prefix: str, mp: Dict[int, str]):
    st.session_state[f"map_df_{prefix}"] = pd.DataFrame({
        "Branch": pd.Series(list(mp.keys()), dtype="Int64"),
        "Port": pd.Series(list(mp.values()), dtype="string"),
    })


def mapping_table(prefix: str, model: str, mode: str, act_ports: List[str]) -> Optional[Dict[int, str]]:
    ss_key = f"map_df_{prefix}"
    spec_key = f"map_branchspec_{prefix}"
    if ss_key not in st.session_state:
        st.session_state[ss_key] = _empty_map_df()
    st.session_state.setdefault(spec_key, "")

    df = st.session_state[ss_key]
    df["Branch"] = df.get("Branch", pd.Series(dtype="Int64")).astype("Int64")
    df["Port"] = df.get("Port", pd.Series(dtype="string")).astype("string").fillna("")

    c1, c2 = st.columns([2, 1])
    with c1:
        st.session_state[spec_key] = st.text_input(
            "Branch spec for auto-map (e.g., 5-8, 11, 13-14)",
            value=st.session_state[spec_key],
            key=f"{spec_key}_input",
        )
    with c2:
        if st.button("Auto-map", key=f"automap_btn_{prefix}"):
            branches = parse_branch_spec(st.session_state[spec_key])
            if branches is None or len(branches) == 0:
                st.error("Invalid or empty branch spec.")
            else:
                mp = auto_map_for_sector(model, mode, branches)
                if not mp:
                    st.error(f"Too many branches ({len(set(branches))}) for active ports ({len(act_ports)}). No repeats allowed.")
                else:
                    _set_mapping_df_from_dict(prefix, mp)
                    st.success(f"Auto-mapped {len(mp)} branches.")
                    st.rerun()

    edited = st.data_editor(
        df,
        key=f"map_editor_{prefix}",
        num_rows="dynamic",
        use_container_width=True,
        hide_index=True,
        column_config={
            "Branch": st.column_config.NumberColumn("RF Branch", min_value=1, step=1, required=True),
            "Port": st.column_config.SelectboxColumn("Port", options=sorted(act_ports), required=True),
        },
    )

    ports = [p for p in edited["Port"].dropna().tolist() if str(p).strip()]
    if len(ports) != len(set(ports)):
        st.error("Branch→Port mapping has repeated Ports. No repeats allowed.")
        return None

    mapping: Dict[int, str] = {}
    for _, r in edited.dropna().iterrows():
        if pd.isna(r.get("Branch")) or str(r.get("Port", "")).strip() == "":
            continue
        br = int(r["Branch"])
        port = str(r["Port"]).upper()
        if port not in set(act_ports):
            st.error(f"Invalid port in mapping: {port}. Active ports: {act_ports}")
            return None
        mapping[br] = port

    if not mapping:
        st.error("Mapping table is empty.")
        return None

    _set_mapping_df_from_dict(prefix, mapping)
    return mapping


def _empty_bwe_df() -> pd.DataFrame:
    return pd.DataFrame({
        "Site": pd.Series(dtype="string"),
        "Band": pd.Series(dtype="string"),
        "ModeOverride": pd.Series(dtype="string"),
        "SectorEquipmentNumber": pd.Series(dtype="string"),
        "SectorCarrierId": pd.Series(dtype="string"),
        "ConfiguredPower": pd.Series(dtype="string"),
        "Attenuation": pd.Series(dtype="string"),
        "Delay": pd.Series(dtype="string"),
        "AntennaUnit": pd.Series(dtype="string"),
        "AntennaSubunit": pd.Series(dtype="string"),
        "RFBranches": pd.Series(dtype="string"),
    })


def bwe_table(prefix: str, bands: List[str], site_choices: List[str]) -> pd.DataFrame:
    ss_key = f"bwe_df_{prefix}"
    if ss_key not in st.session_state:
        st.session_state[ss_key] = _empty_bwe_df()

    df = st.session_state[ss_key]
    for c in df.columns:
        df[c] = df.get(c, pd.Series(dtype="string")).astype("string").fillna("")

    edited = st.data_editor(
        df,
        key=f"bwe_editor_{prefix}",
        num_rows="dynamic",
        use_container_width=True,
        hide_index=True,
        column_config={
            "Site": st.column_config.SelectboxColumn("Site", options=site_choices, required=True),
            "Band": st.column_config.SelectboxColumn("Band", options=bands, required=True),
            "ModeOverride": st.column_config.SelectboxColumn("Mode override (optional)", options=[""] + ALL_MODES),
            "SectorEquipmentNumber": st.column_config.TextColumn("SE Number", required=True),
            "SectorCarrierId": st.column_config.TextColumn("SC Id", required=True),
            "ConfiguredPower": st.column_config.TextColumn("Power", required=True),
            "Attenuation": st.column_config.TextColumn("Att", required=True),
            "Delay": st.column_config.TextColumn("Delay", required=True),
            "AntennaUnit": st.column_config.TextColumn("AU", required=True),
            "AntennaSubunit": st.column_config.TextColumn("ASU", required=True),
            "RFBranches": st.column_config.TextColumn("RF Branches (comma)", required=True),
        },
    )

    for c in edited.columns:
        edited[c] = edited.get(c, pd.Series(dtype="string")).astype("string").fillna("")

    st.session_state[ss_key] = edited
    return edited


def bwe_df_to_params(bwe_df: pd.DataFrame, default_site: str) -> List[BWEParams]:
    params: List[BWEParams] = []
    for idx, row in bwe_df.iterrows():
        required = ["Band", "SectorEquipmentNumber", "SectorCarrierId", "ConfiguredPower", "Attenuation", "Delay", "AntennaUnit", "AntennaSubunit", "RFBranches"]
        if any(str(row.get(k, "")).strip() == "" for k in required):
            continue

        rfbs = parse_int_list(str(row["RFBranches"]))
        if rfbs is None or len(rfbs) == 0:
            raise ValueError(f"BWE row {idx+1}: invalid RFBranches '{row['RFBranches']}'")

        site = str(row.get("Site", "")).strip() or default_site
        mode_override = str(row.get("ModeOverride", "")).strip() or None

        params.append(BWEParams(
            band=str(row["Band"]),
            bwe_index=int(idx),
            sector_equipment_number=str(row["SectorEquipmentNumber"]),
            sector_carrier_id=str(row["SectorCarrierId"]),
            configured_power=str(row["ConfiguredPower"]),
            attenuation=str(row["Attenuation"]),
            delay=str(row["Delay"]),
            antenna_unit=str(row["AntennaUnit"]),
            antenna_subunit=str(row["AntennaSubunit"]),
            rfbs=sorted(set(rfbs)),
            site=site,
            mode_override=mode_override,
        ))

    return params


def _empty_rilinks_df() -> pd.DataFrame:
    return pd.DataFrame({"Site": pd.Series(dtype="string"), "RiLinkId": pd.Series(dtype="string"), "riPortRef1": pd.Series(dtype="string"), "riPortRef2": pd.Series(dtype="string")}).fillna("")


def rilinks_table(prefix: str, default_ref2: str, site_choices: List[str], default_site: str) -> List[RiLinkConfig]:
    ss_key = f"rilinks_df_{prefix}"
    if ss_key not in st.session_state:
        df = _empty_rilinks_df()
        df.loc[0, "Site"] = default_site
        df.loc[0, "riPortRef2"] = default_ref2
        st.session_state[ss_key] = df

    df = st.session_state[ss_key]
    for c in df.columns:
        df[c] = df.get(c, pd.Series(dtype="string")).astype("string").fillna("")

    edited = st.data_editor(
        df,
        key=f"rilinks_editor_{prefix}",
        num_rows="dynamic",
        use_container_width=True,
        hide_index=True,
        column_config={
            "Site": st.column_config.SelectboxColumn("Site", options=site_choices, required=True),
            "RiLinkId": st.column_config.TextColumn("RiLink Id"),
            "riPortRef1": st.column_config.TextColumn("riPortRef1 (FDN)"),
            "riPortRef2": st.column_config.TextColumn("riPortRef2 (FDN)"),
        },
    )

    rilinks: List[RiLinkConfig] = []
    for _, row in edited.iterrows():
        if str(row.get("RiLinkId", "")).strip() and str(row.get("riPortRef1", "")).strip() and str(row.get("riPortRef2", "")).strip():
            rilinks.append(RiLinkConfig(
                link_number=str(row["RiLinkId"]).strip(),
                ri_port_ref1=str(row["riPortRef1"]).strip(),
                ri_port_ref2=str(row["riPortRef2"]).strip(),
                site=str(row.get("Site", default_site)).strip() or default_site,
            ))

    st.session_state[ss_key] = edited
    return rilinks

# ============================
# AUG grouping + render once per AUG (per site)
# ============================

def sectors_by_aug(sectors: List[SectorConfig]) -> Dict[str, List[SectorConfig]]:
    groups: Dict[str, List[SectorConfig]] = {}
    for s in sectors:
        groups.setdefault(s.aug_group, []).append(s)
    return groups


def find_owner_sector_for_branch(sectors: List[SectorConfig], branch: int) -> SectorConfig:
    owners = [s for s in sectors if branch in s.branch_port_map]
    if len(owners) != 1:
        raise ValueError(f"Branch {branch} must exist in exactly one radio mapping within this AUG. Found {len(owners)}.")
    return owners[0]


def render_antenna_units_for_aug(site: str, aug_group: str, sectors: List[SectorConfig]) -> List[str]:
    blocks: List[str] = []

    # Include params per site, but if a radio is shared, include its params from both sites
    all_params: List[BWEParams] = []
    for sec in sectors:
        all_params.extend(params_visible_for_site(sec, site))

    for au in sorted({p.antenna_unit for p in all_params}):
        mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"AntennaUnitGroup={aug_group}", f"AntennaUnit={au}")
        params = {
            "antennaModelNumber": '""',
            "antennaSerialNumber": '""',
            "antennaUnitId": f'"{au}"',
            "mechanicalAntennaBearing": "-1000",
            "mechanicalAntennaTilt": "0",
            "positionWithinSector": '""',
            "sectorLabel": '""',
        }
        blocks.append(render_block("create", mo_fdn, params))

    for au, asu in sorted({(p.antenna_unit, p.antenna_subunit) for p in all_params}):
        mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1", f"AntennaUnitGroup={aug_group}", f"AntennaUnit={au}", f"AntennaSubunit={asu}")
        params = {
            "antennaSubunitId": str(asu),
            "azimuthHalfPowerBeamwidth": "65",
            "commonChBeamfrmPortMap": "CROSS_POLARIZED",
            "maxTotalTilt": "300",
            "minTotalTilt": "-300",
        }
        blocks.append(render_block("create", mo_fdn, params))

    return blocks


def render_auports_for_aug(site: str, aug_group: str, sectors: List[SectorConfig]) -> List[str]:
    blocks: List[str] = []

    # AuPorts are created PER (AntennaUnit, AntennaSubunit) using the branches that belong to that AU/ASU.
    # This avoids AuPort reference mismatches when multiple AUs exist in the same AUG.

    branches_by_auasu: Dict[Tuple[str, str], List[int]] = {}

    for sec in sectors:
        for p in params_visible_for_site(sec, site):
            key = (str(p.antenna_unit), str(p.antenna_subunit))
            branches_by_auasu.setdefault(key, [])
            branches_by_auasu[key].extend(rx_branches_for_entry(sec, p))

    # De-dup and sort per AU/ASU
    for k in list(branches_by_auasu.keys()):
        branches_by_auasu[k] = sorted(set(branches_by_auasu[k]))

    for (au, asu), brs in sorted(branches_by_auasu.items()):
        n_ports = len(brs)
        if n_ports == 0:
            continue
        for port_id in range(1, n_ports + 1):
            mo_fdn = fdn(
                "SubNetwork=ONRM_ROOT_MO",
                f"MeContext={site}",
                me(site),
                "Equipment=1",
                f"AntennaUnitGroup={aug_group}",
                f"AntennaUnit={au}",
                f"AntennaSubunit={asu}",
                f"AuPort={port_id}",
            )
            blocks.append(render_block("create", mo_fdn, {"auPortId": f'"{port_id}"', "userLabel": "<empty>"}))

    return blocks

    # Use all AU/ASU pairs from visible params
    all_params: List[BWEParams] = []
    for sec in sectors:
        all_params.extend(params_visible_for_site(sec, site))

    for au, asu in sorted({(p.antenna_unit, p.antenna_subunit) for p in all_params}):
        for port_id in range(1, n_ports + 1):
            mo_fdn = fdn("SubNetwork=ONRM_ROOT_MO", f"MeContext={site}", me(site), "Equipment=1",
                         f"AntennaUnitGroup={aug_group}", f"AntennaUnit={au}", f"AntennaSubunit={asu}", f"AuPort={port_id}")
            blocks.append(render_block("create", mo_fdn, {"auPortId": f'"{port_id}"', "userLabel": "<empty>"}))

    return blocks


def render_rfbranches_for_aug(site: str, aug_group: str, sectors: List[SectorConfig]) -> List[str]:
    blocks: List[str] = []

    # Determine branch set using expanded RX branches and track which AU/ASU each branch belongs to.
    branch_set: Set[int] = set()
    all_params: List[Tuple[SectorConfig, BWEParams]] = []
    branch_to_auasu: Dict[int, Tuple[str, str]] = {}

    for sec in sectors:
        for p in params_visible_for_site(sec, site):
            all_params.append((sec, p))
            rx_brs = rx_branches_for_entry(sec, p)
            for b in rx_brs:
                branch_set.add(b)
                branch_to_auasu.setdefault(b, (str(p.antenna_unit), str(p.antenna_subunit)))

    uniq_branches = sorted(branch_set)

    # Build per-AU/ASU AuPort indices (1..N) within each AU/ASU
    branches_by_auasu: Dict[Tuple[str, str], List[int]] = {}
    for b, key in branch_to_auasu.items():
        branches_by_auasu.setdefault(key, []).append(b)
    for k in list(branches_by_auasu.keys()):
        branches_by_auasu[k] = sorted(set(branches_by_auasu[k]))

    auport_index: Dict[Tuple[str, str], Dict[int, int]] = {
        k: {b: i + 1 for i, b in enumerate(brs)} for k, brs in branches_by_auasu.items()
    }

    # Choose a source per branch (prefer the band associated with the port, if defined)
    source_by_branch: Dict[int, Tuple[SectorConfig, BWEParams]] = {}
    for sec, p in all_params:
        for b in rx_branches_for_entry(sec, p):
            owner = find_owner_sector_for_branch(sectors, b)
            if owner != sec:
                continue
            port = rfport_for_branch(owner, b)
            pref_band = band_preference_for_port(owner.radio_model, port)
            if b not in source_by_branch:
                source_by_branch[b] = (sec, p)
            else:
                if pref_band is not None and p.band == pref_band:
                    source_by_branch[b] = (sec, p)

    for b in uniq_branches:
        # If not chosen via carriers (e.g., shared site with no carriers), fall back to any owner
        if b not in source_by_branch:
            owner = find_owner_sector_for_branch(sectors, b)
            p = params_visible_for_site(owner, site)[0] if params_visible_for_site(owner, site) else owner.params[0]
            source_by_branch[b] = (owner, p)

        sec, p = source_by_branch[b]
        port_letter = rfport_for_branch(sec, b)
        rru = preferred_rru_for_band(sec, p.band)

        au, asu = branch_to_auasu.get(b, (str(p.antenna_unit), str(p.antenna_subunit)))
        au_port_id = auport_index.get((au, asu), {}).get(b, 1)

        mo_fdn = fdn(
            "SubNetwork=ONRM_ROOT_MO",
            f"MeContext={site}",
            me(site),
            "Equipment=1",
            f"AntennaUnitGroup={aug_group}",
            f"RfBranch={b}",
        )

        au_ref = fdn(
            "SubNetwork=ONRM_ROOT_MO",
            f"MeContext={site}",
            me(site),
            "Equipment=1",
            f"AntennaUnitGroup={aug_group}",
            f"AntennaUnit={au}",
            f"AntennaSubunit={asu}",
            f"AuPort={au_port_id}",
        )

        rf_ref = fdn(
            "SubNetwork=ONRM_ROOT_MO",
            f"MeContext={site}",
            me(site),
            "Equipment=1",
            f"FieldReplaceableUnit=RRU-{rru}",
            f"RfPort={port_letter}",
        )

        create_params = {
            "auPortRef": f'"{au_ref}"',
            "dlAttenuation": replicate_15(p.attenuation),
            "dlAttenuationPerFqRange": "[-1, -1]",
            "dlTrafficDelay": replicate_15(p.delay),
            "dlTrafficDelayPerFqRange": "[-1, -1]",
            "rfBranchId": f'"{b}"',
            "rfPortRef": f'"{rf_ref}"',
            "tmaRef": "<empty>",
            "ulAttenuation": replicate_15(p.attenuation),
            "ulAttenuationPerFqRange": "[-1, -1]",
            "ulTrafficDelay": replicate_15(p.delay),
            "ulTrafficDelayPerFqRange": "[-1, -1]",
            "userLabel": "<empty>",
        }

        blocks.append(render_block("create", mo_fdn, create_params))
        blocks.append(render_block("set", mo_fdn, {"auPortRef": f'["{au_ref}"]', "rfPortRef": f'["{rf_ref}"]'}))

    return blocks

# ============================
# Bulk generator per site
# ============================

def generate_bulk_for_site(cfg: WizardConfig, site: str) -> str:
    blocks: List[str] = []

    # RRUs + ports for this site
    for rru, model, shared_ext in unique_rrus_for_site(cfg, site):
        blocks.append(render_rru(site, rru, shared_ext))
        blocks.extend(render_rfports(site, model, rru))
        blocks.extend(render_riports(site, rru))
        blocks.extend(render_alarmports(site, rru))

    # Include sectors that either have carriers on this site OR are configured to exist in both sites
    sectors_site = [s for s in cfg.sectors if any(p.site == site for p in s.params) or s.create_in_both_sites]
    groups = sectors_by_aug(sectors_site)

    # AU/ASU + AuPorts once per AUG
    for aug_group, secs in groups.items():
        blocks.extend(render_antenna_units_for_aug(site, aug_group, secs))
        blocks.extend(render_auports_for_aug(site, aug_group, secs))

    # RiLinks: only those belonging to this site
    for sector in sectors_site:
        blocks.extend(render_rilinks(site, sector))

    # RfBranches once per AUG
    for aug_group, secs in groups.items():
        blocks.extend(render_rfbranches_for_aug(site, aug_group, secs))

    # SectorEquipmentFunction + (LTE SectorCarrier OR NR NRSectorCarrier) only for entries on this site
    node_tech = cfg.site_tech.get(site, 'LTE') if hasattr(cfg, 'site_tech') else 'LTE'
    for sector in sectors_site:
        for p in [x for x in sector.params if x.site == site]:
            blocks.append(render_sector_equipment_function(site, sector, p))
            car_t = str(getattr(p, 'tech', '') or '').strip().upper()
            if car_t in ('LTE', 'NR'):
                eff = car_t
            else:
                eff = 'NR' if str(node_tech).upper() == 'NR' else 'LTE'
                if str(node_tech).upper() == 'LTE+NR':
                    eff = 'LTE'
            if eff == 'NR':
                blocks.extend(render_nr_sector_carrier(site, sector, p))
            else:
                blocks.extend(render_sector_carrier(site, sector, p))

    # VSWR
    if cfg.vswr_enable:
        for rru, model, shared_ext in unique_rrus_for_site(cfg, site):
            model_ports = set(RADIO_LIBRARY[model]["ports"])
            ports = [p for p in cfg.vswr_ports if p in model_ports]
            blocks.extend(render_vswr(site, rru, cfg.vswr_sensitivity, ports))

    return "\n\n".join(blocks) + "\n"

# ============================
# Validation
# ============================

def validate_mode_for_band(model: str, mode: str, band: str) -> Optional[str]:
    md = RADIO_LIBRARY[model]
    allowed_by_band = md.get("allowed_modes_by_band", {})
    allowed = allowed_by_band.get(band, [])
    if mode not in allowed:
        return f"Mode '{mode}' is not allowed for band '{band}' on model {model}. Allowed: {allowed}"
    return None


def validate_per_band_mode_rules(model: str, radio_mode: str, params: List[BWEParams]) -> Optional[str]:
    md = RADIO_LIBRARY[model]
    allow_per_band = bool(md.get("allow_per_band_mode"))
    for p in params:
        eff_mode = p.mode_override or radio_mode
        if (not allow_per_band) and p.mode_override and p.mode_override != radio_mode:
            return f"Mode override '{p.mode_override}' is not allowed for model {model}. Use the radio Mode '{radio_mode}'."
        err = validate_mode_for_band(model, eff_mode, p.band)
        if err:
            return err
    return None

# ============================
# Streamlit UI
# ============================

def pick_folder_dialog() -> Optional[str]:
    if tk is None or filedialog is None:
        return None
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        folder = filedialog.askdirectory(title="Select output folder for generated ENM bulk scripts")
        root.destroy()
        return folder or None
    except Exception:
        return None


def init_state():
    st.session_state.setdefault("output_dir", "")
    st.session_state.setdefault("generated", False)
    st.session_state.setdefault("bulk_site1", "")
    st.session_state.setdefault("bulk_site2", "")
    st.session_state.setdefault("json_text", "")


def reset_table_state():
    for k in list(st.session_state.keys()):
        if k.startswith(("bwe_df_", "map_df_", "rilinks_df_", "radios_df_", "map_branchspec_")):
            del st.session_state[k]


def radio_main():
    # (moved to Home_merged_supabase_auth.py) st.set_page_config(...) 
    init_state()

    st.title("E:// Radio CLI Script — v2")

    # Sidebar: ONLY project + VSWR + output. (No default radio model/base widgets.)
    with st.sidebar:
        st.header("Project")
        site1 = st.text_input("Site-1 name (MeContext)")
        site2_enable = st.toggle("Also generate for Site-2?", value=False)
        site2 = st.text_input("Site-2 name (MeContext)", disabled=not site2_enable)

        st.divider()

        # Technology per site
        site1_tech = st.selectbox('Site-1 Technology', options=['LTE', 'NR', 'LTE+NR'], index=0)
        site2_tech = None
        if site2_enable:
            site2_tech = st.selectbox('Site-2 Technology', options=['LTE', 'NR', 'LTE+NR'], index=0)

        st.divider()
        st.subheader("VSWR")
        vswr_enable = st.toggle("Generate VSWR set blocks", value=True)
        vswr_sensitivity = st.text_input("VSWR sensitivity", value="70")
        vswr_ports = st.multiselect("VSWR Ports", options=["A","B","C","D","E","F","G","H"], default=["A","B","C","D","E","F","G","H"])

        st.divider()
        st.subheader("Output")
        c1, c2 = st.columns([1, 1])
        with c1:
            if st.button("Pick output folder (native dialog)"):
                folder = pick_folder_dialog()
                if folder:
                    st.session_state.output_dir = folder
        with c2:
            st.session_state.output_dir = st.text_input("Output folder path (optional)", value=st.session_state.output_dir)

        st.divider()
        if st.button("Reset all table inputs"):
            reset_table_state()
            st.rerun()

    if site1.strip() == "":
        st.info("Fill in Site-1 name (MeContext) to proceed.")
        return

    sites = [site1.strip()]
    if site2_enable and site2.strip():
        sites.append(site2.strip())

    # ---------------------------
    # Flat tables state
    # ---------------------------
    def _empty_radios_flat() -> pd.DataFrame:
        return pd.DataFrame({
            "RadioKey": pd.Series(dtype="string"),
            "AUG": pd.Series(dtype="string"),
            "RadioSite": pd.Series(dtype="string"),
            "RadioModel": pd.Series(dtype="string"),
            "RadioMode": pd.Series(dtype="string"),
            "RRUBase": pd.Series(dtype="string"),
            "CreateInBothSites": pd.Series(dtype="bool"),
            "SharedSE": pd.Series(dtype="bool"),
            "SharedSENumber": pd.Series(dtype="string"),
        }).fillna("")

    def _empty_mapping_flat() -> pd.DataFrame:
        return pd.DataFrame({
            "RadioKey": pd.Series(dtype="string"),
            "Branch": pd.Series(dtype="Int64"),
            "Port": pd.Series(dtype="string"),
        }).fillna("")

    def _empty_carriers_flat() -> pd.DataFrame:
        return pd.DataFrame({
            "RadioKey": pd.Series(dtype="string"),
            "Site": pd.Series(dtype="string"),
            "CarrierTech": pd.Series(dtype="string"),
            "Band": pd.Series(dtype="string"),
            "ModeOverride": pd.Series(dtype="string"),
            "SectorEquipmentNumber": pd.Series(dtype="string"),
            "SectorCarrierId": pd.Series(dtype="string"),
            "ConfiguredPower": pd.Series(dtype="string"),
            "Attenuation": pd.Series(dtype="string"),
            "Delay": pd.Series(dtype="string"),
            "AntennaUnit": pd.Series(dtype="string"),
            "AntennaSubunit": pd.Series(dtype="string"),
            "RFBranches": pd.Series(dtype="string"),
        }).fillna("")

    def _empty_rilinks_flat() -> pd.DataFrame:
        return pd.DataFrame({
            "RadioKey": pd.Series(dtype="string"),
            "Site": pd.Series(dtype="string"),
            "RiLinkId": pd.Series(dtype="string"),
            "riPortRef1": pd.Series(dtype="string"),
            "riPortRef2": pd.Series(dtype="string"),
        }).fillna("")

    st.session_state.setdefault("radios_flat_df", _empty_radios_flat())
    st.session_state.setdefault("mapping_flat_df", _empty_mapping_flat())
    st.session_state.setdefault("carriers_flat_df", _empty_carriers_flat())
    st.session_state.setdefault("rilinks_flat_df", _empty_rilinks_flat())

    # 1) Radios table
    st.subheader("1) Radios")
    # Quick add: append a new radio row with an auto-generated RadioKey
    if st.button("+ Add radio row"):
        df0 = st.session_state.radios_flat_df.copy()
        df0["RadioKey"] = df0.get("RadioKey", "").astype(str).str.strip()
        existing = {k for k in df0["RadioKey"].tolist() if k}
        nxt = 1
        while f"R{nxt}" in existing:
            nxt += 1
        new_row = {c: "" for c in df0.columns}
        new_row["RadioKey"] = f"R{nxt}"
        new_row["CreateInBothSites"] = False
        new_row["SharedSE"] = False
        df0 = pd.concat([df0, pd.DataFrame([new_row])], ignore_index=True)
        st.session_state.radios_flat_df = df0
        st.rerun()
    model_options = [""] + sorted(RADIO_LIBRARY.keys())
    with st.form("radios_flat_form"):
        radios_df = st.data_editor(
            st.session_state.radios_flat_df,
            key="radios_flat_editor",
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            column_config={
                "RadioKey": st.column_config.TextColumn("RadioKey (unique)", required=True),
                "AUG": st.column_config.TextColumn("AUG", required=True),
                "RadioSite": st.column_config.SelectboxColumn("RadioSite", options=sites, required=True),
                "RadioModel": st.column_config.SelectboxColumn("Model", options=model_options, required=True),
                "RadioMode": st.column_config.SelectboxColumn("Mode", options=[""] + ALL_MODES, required=True),
                "RRUBase": st.column_config.TextColumn("RRU Base", required=True),
                "CreateInBothSites": st.column_config.CheckboxColumn("Create in both sites?"),
                "SharedSE": st.column_config.CheckboxColumn("Shared SE?"),
                "SharedSENumber": st.column_config.TextColumn("Shared SE Number"),
            },
        )
        applied_radios = st.form_submit_button("Apply radios")
        if applied_radios:
            fixed = radios_df.copy()
            fixed["RadioKey"] = fixed.get("RadioKey", "").astype(str).str.strip()
            existing = {k for k in fixed["RadioKey"].tolist() if k}
            nxt = 1
            for ii in range(len(fixed)):
                if not str(fixed.at[ii, "RadioKey"]).strip():
                    while f"R{nxt}" in existing:
                        nxt += 1
                    fixed.at[ii, "RadioKey"] = f"R{nxt}"
                    existing.add(f"R{nxt}")
                    nxt += 1
            radios_df = fixed
        st.session_state.radios_flat_df = radios_df

    # Helper: list of radio keys
    radio_keys = sorted([str(x).strip() for x in radios_df.get("RadioKey", pd.Series(dtype="string")).tolist() if str(x).strip()])

    # 2) Mapping table
    st.subheader("2) Branch ↔ Port Mapping")

    # Auto-map helper
    st.markdown("**Auto-map helper (optional):** Choose RadioKey + branch spec (e.g. `5-12`) then click Auto-map.")
    a1, a2, a3 = st.columns([2, 2, 1])
    with a1:
        rk_auto = st.selectbox("RadioKey", options=[""] + radio_keys)
    with a2:
        spec = st.text_input("Branch spec", value="")
    with a3:
        if st.button("Auto-map"):
            if not rk_auto:
                st.error("Select a RadioKey")
            else:
                rr = radios_df[radios_df["RadioKey"].astype(str).str.strip() == rk_auto]
                if rr.empty:
                    st.error("RadioKey not found")
                else:
                    model = str(rr.iloc[0]["RadioModel"]).strip()
                    mode = str(rr.iloc[0]["RadioMode"]).strip()
                    branches = parse_branch_spec(spec)
                    if not model or not mode:
                        st.error("Select Model and Mode in Radios table first")
                    elif branches is None or len(branches) == 0:
                        st.error("Invalid branch spec")
                    else:
                        mp = auto_map_for_sector(model, mode, branches)
                        if not mp:
                            st.error("Too many branches for active ports")
                        else:
                            df_old = st.session_state.mapping_flat_df.copy()
                            df_old["RadioKey"] = df_old.get("RadioKey", "").astype(str)
                            df_old = df_old[df_old["RadioKey"].str.strip() != rk_auto]
                            add = pd.DataFrame({
                                "RadioKey": [rk_auto] * len(mp),
                                "Branch": pd.Series(list(mp.keys()), dtype="Int64"),
                                "Port": pd.Series(list(mp.values()), dtype="string"),
                            })
                            st.session_state.mapping_flat_df = pd.concat([df_old, add], ignore_index=True)
                            st.success(f"Auto-mapped {len(mp)} branches for {rk_auto}")
                            st.rerun()

    with st.form("mapping_flat_form"):
        mapping_df = st.data_editor(
            st.session_state.mapping_flat_df,
            key="mapping_flat_editor",
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            column_config={
                "RadioKey": st.column_config.SelectboxColumn("RadioKey", options=[""] + radio_keys, required=True),
                "Branch": st.column_config.NumberColumn("RF Branch", min_value=1, step=1, required=True),
                "Port": st.column_config.TextColumn("Port", required=True),
            },
        )
        st.form_submit_button("Apply mapping")
    st.session_state.mapping_flat_df = mapping_df

    # 3) Carriers
    st.subheader("3) Carriers / Sector inputs")
    with st.form("carriers_flat_form"):
        carriers_df = st.data_editor(
            st.session_state.carriers_flat_df,
            key="carriers_flat_editor",
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            column_config={
                "RadioKey": st.column_config.SelectboxColumn("RadioKey", options=[""] + radio_keys, required=True),
                "Site": st.column_config.SelectboxColumn("Site", options=sites, required=True),
                "CarrierTech": st.column_config.SelectboxColumn("Tech", options=["", "LTE", "NR"], required=False),
                "Band": st.column_config.SelectboxColumn("Band", options=[""] + ALL_BANDS, required=True),
                "ModeOverride": st.column_config.SelectboxColumn("ModeOverride (optional)", options=[""] + ALL_MODES),
                "SectorEquipmentNumber": st.column_config.TextColumn("SE Number", required=True),
                "SectorCarrierId": st.column_config.TextColumn("SC Id", required=True),
                "ConfiguredPower": st.column_config.TextColumn("Power", required=True),
                "Attenuation": st.column_config.TextColumn("Att", required=True),
                "Delay": st.column_config.TextColumn("Delay", required=True),
                "AntennaUnit": st.column_config.TextColumn("AU", required=True),
                "AntennaSubunit": st.column_config.TextColumn("ASU", required=True),
                "RFBranches": st.column_config.TextColumn("RF Branches (comma)", required=True),
            },
        )
        st.form_submit_button("Apply carriers")
    st.session_state.carriers_flat_df = carriers_df

    # 4) RiLinks
    st.subheader("4) RiLinks")
    st.caption("Tip: Select RadioKey and Site, then add DATA_1 or DATA_2 row. RiLinkId stays blank for you to fill.")
    c_add1, c_add2, c_add3, c_add4 = st.columns([2, 2, 1, 1])
    with c_add1:
        rk_add_rl = st.selectbox("RadioKey for RiLinks", options=[""] + radio_keys, key="rk_add_rl")
    with c_add2:
        site_add_rl = st.selectbox("Site for RiLinks", options=sites, key="site_add_rl")
    def _append_rl_row(_port: str):
        df0 = st.session_state.rilinks_flat_df.copy()
        # Look up RRUBase for this RadioKey
        tmp = st.session_state.radios_flat_df.copy()
        tmp["RadioKey"] = tmp.get("RadioKey", "").astype(str).str.strip()
        tmp["RRUBase"] = tmp.get("RRUBase", "").astype(str).str.strip()
        rru = ""
        hit = tmp[tmp["RadioKey"] == str(rk_add_rl).strip()]
        if not hit.empty:
            rru = str(hit.iloc[0]["RRUBase"]).strip()
        prefix = f"SubNetwork=ONRM_ROOT_MO,MeContext={site_add_rl},ManagedElement={site_add_rl},Equipment=1,"
        ref2 = ""
        if rru:
            ref2 = f"SubNetwork=ONRM_ROOT_MO,MeContext={site_add_rl},ManagedElement={site_add_rl},Equipment=1,FieldReplaceableUnit=RRU-{rru},RiPort={_port}"
        new_row = {
            "RadioKey": rk_add_rl,
            "Site": site_add_rl,
            "RiLinkId": "",
            "riPortRef1": prefix,
            "riPortRef2": ref2,
        }
        df0 = pd.concat([df0, pd.DataFrame([new_row])], ignore_index=True).fillna("")
        st.session_state.rilinks_flat_df = df0
        st.rerun()
    with c_add3:
        if st.button("+ Add DATA_1", key="btn_add_rl_data1"):
            if str(rk_add_rl).strip() and str(site_add_rl).strip():
                _append_rl_row("DATA_1")
            else:
                st.warning("Select RadioKey and Site first.")
    with c_add4:
        if st.button("+ Add DATA_2", key="btn_add_rl_data2"):
            if str(rk_add_rl).strip() and str(site_add_rl).strip():
                _append_rl_row("DATA_2")
            else:
                st.warning("Select RadioKey and Site first.")
    with st.form("rilinks_flat_form"):
        rilinks_df = st.data_editor(
            st.session_state.rilinks_flat_df,
            key="rilinks_flat_editor",
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            column_config={
                "RadioKey": st.column_config.SelectboxColumn("RadioKey", options=[""] + radio_keys, required=True),
                "Site": st.column_config.SelectboxColumn("Site", options=sites, required=True),
                "RiLinkId": st.column_config.TextColumn("RiLink Id", required=True),
                "riPortRef1": st.column_config.TextColumn("riPortRef1 (FDN)", required=True),
                "riPortRef2": st.column_config.TextColumn("riPortRef2 (FDN)", required=True),
            },
        )
        applied_rl = st.form_submit_button("Apply RiLinks")
        if applied_rl:
            df_rl = rilinks_df.copy()
            df_rl["RadioKey"] = df_rl.get("RadioKey", "").astype(str).str.strip()
            df_rl["Site"] = df_rl.get("Site", "").astype(str).str.strip()

            # Map RadioKey -> RRUBase from radios table
            tmp = radios_df.copy()
            tmp["RadioKey"] = tmp.get("RadioKey", "").astype(str).str.strip()
            tmp["RRUBase"] = tmp.get("RRUBase", "").astype(str).str.strip()
            rk_to_rru = {r["RadioKey"]: r["RRUBase"] for _, r in tmp.iterrows() if r["RadioKey"]}

            # Track assigned DATA ports per (RadioKey, Site) for rows where ref2 is missing
            assigned = {}
            for ii in range(len(df_rl)):
                rk = str(df_rl.at[ii, "RadioKey"]).strip()
                stt = str(df_rl.at[ii, "Site"]).strip()
                if not rk or not stt:
                    continue

                # Prefill riPortRef1 prefix up to Equipment=1,
                if not str(df_rl.at[ii, "riPortRef1"]).strip():
                    df_rl.at[ii, "riPortRef1"] = f"SubNetwork=ONRM_ROOT_MO,MeContext={stt},ManagedElement={stt},Equipment=1,"

                # Prefill riPortRef2 if empty: first DATA_1 then DATA_2 per RadioKey+Site
                if not str(df_rl.at[ii, "riPortRef2"]).strip():
                    rru = rk_to_rru.get(rk, "")
                    if rru:
                        key = (rk, stt)
                        used = assigned.setdefault(key, set())
                        port = "DATA_1" if "DATA_1" not in used else "DATA_2" if "DATA_2" not in used else "DATA_1"
                        used.add(port)
                        df_rl.at[ii, "riPortRef2"] = (
                            f"SubNetwork=ONRM_ROOT_MO,MeContext={stt},ManagedElement={stt},Equipment=1,"
                            f"FieldReplaceableUnit=RRU-{rru},RiPort={port}"
                        )

            rilinks_df = df_rl
        st.session_state.rilinks_flat_df = rilinks_df

    st.divider()
    generate = st.button("Generate scripts", type="primary")

    if generate:
        errors: List[str] = []

        # Clean radios
        r = radios_df.copy()
        for c in ["RadioKey","AUG","RadioSite","RadioModel","RadioMode","RRUBase"]:
            if c in r.columns:
                r[c] = r[c].astype(str).str.strip()
        r = r[r["RadioKey"] != ""]

        if r.empty:
            errors.append("No radios defined.")

        if len(set(r["RadioKey"])) != len(r["RadioKey"]):
            errors.append("RadioKey must be unique.")

        for _, row in r.iterrows():
            rk = row["RadioKey"]
            if any(row[x] == "" for x in ["AUG","RadioSite","RadioModel","RadioMode","RRUBase"]):
                errors.append(f"Radio {rk}: missing required fields.")
                continue
            if row["RadioModel"] not in RADIO_LIBRARY:
                errors.append(f"Radio {rk}: unknown model {row['RadioModel']}.")
                continue
            if row["RadioMode"] not in RADIO_LIBRARY[row["RadioModel"]]["modes"]:
                errors.append(f"Radio {rk}: invalid mode {row['RadioMode']} for model {row['RadioModel']}.")
                continue
            if bool(row.get("CreateInBothSites", False)) and (not site2_enable or not site2.strip()):
                errors.append(f"Radio {rk}: CreateInBothSites is TRUE but Site-2 not configured.")
            if bool(row.get("SharedSE", False)) and str(row.get("SharedSENumber", "")).strip() == "":
                errors.append(f"Radio {rk}: SharedSE enabled but SharedSENumber empty.")

        # Mapping per radio
        mp_df = mapping_df.copy()
        mp_df["RadioKey"] = mp_df.get("RadioKey", "").astype(str).str.strip()
        mp_df["Port"] = mp_df.get("Port", "").astype(str).str.strip().str.upper()
        mp_df = mp_df[mp_df["RadioKey"] != ""]

        map_by_radio: Dict[str, Dict[int, str]] = {}
        for rk, grp in mp_df.groupby("RadioKey"):
            ports_seen: Set[str] = set()
            mapp: Dict[int, str] = {}
            for _, rr in grp.iterrows():
                if pd.isna(rr.get("Branch")):
                    continue
                br = int(rr["Branch"])
                port = str(rr["Port"]).upper()
                if port in ports_seen:
                    errors.append(f"Mapping {rk}: port {port} repeated.")
                ports_seen.add(port)
                mapp[br] = port
            if mapp:
                map_by_radio[rk] = mapp

        # Carriers per radio
        car_df = carriers_df.copy()
        car_df["RadioKey"] = car_df.get("RadioKey", "").astype(str).str.strip()
        car_df = car_df[car_df["RadioKey"] != ""]

        params_by_radio: Dict[str, List[BWEParams]] = {rk: [] for rk in r["RadioKey"].tolist()}

        for idx, row in car_df.iterrows():
            rk = str(row.get("RadioKey", "")).strip()
            if rk not in params_by_radio:
                errors.append(f"Carrier row {idx+1}: unknown RadioKey {rk}.")
                continue
            required = ["Site","Band","SectorEquipmentNumber","SectorCarrierId","ConfiguredPower","Attenuation","Delay","AntennaUnit","AntennaSubunit","RFBranches"]
            if any(str(row.get(k, "")).strip() == "" for k in required):
                errors.append(f"Carrier row {idx+1} (Radio {rk}): missing required fields.")
                continue
            rfbs = parse_int_list(str(row["RFBranches"]))
            if rfbs is None or len(rfbs) == 0:
                errors.append(f"Carrier row {idx+1} (Radio {rk}): invalid RFBranches {row['RFBranches']}.")
                continue
            params_by_radio[rk].append(BWEParams(
                band=str(row["Band"]).strip(),
                tech=str(row.get("CarrierTech", "")).strip() or 'AUTO',
                    bwe_index=int(idx),
                sector_equipment_number=str(row["SectorEquipmentNumber"]).strip(),
                sector_carrier_id=str(row["SectorCarrierId"]).strip(),
                configured_power=str(row["ConfiguredPower"]).strip(),
                attenuation=str(row["Attenuation"]).strip(),
                delay=str(row["Delay"]).strip(),
                antenna_unit=str(row["AntennaUnit"]).strip(),
                antenna_subunit=str(row["AntennaSubunit"]).strip(),
                rfbs=sorted(set(rfbs)),
                site=str(row["Site"]).strip(),
                mode_override=str(row.get("ModeOverride", "")).strip() or None,
            ))

        # RiLinks per radio
        rl_df = rilinks_df.copy()
        rl_df["RadioKey"] = rl_df.get("RadioKey", "").astype(str).str.strip()
        rl_df = rl_df[rl_df["RadioKey"] != ""]

        rilinks_by_radio: Dict[str, List[RiLinkConfig]] = {rk: [] for rk in r["RadioKey"].tolist()}
        for idx, row in rl_df.iterrows():
            rk = str(row.get("RadioKey", "")).strip()
            if rk not in rilinks_by_radio:
                errors.append(f"RiLink row {idx+1}: unknown RadioKey {rk}.")
                continue
            required = ["Site","RiLinkId","riPortRef1","riPortRef2"]
            if any(str(row.get(k, "")).strip() == "" for k in required):
                errors.append(f"RiLink row {idx+1} (Radio {rk}): missing required fields.")
                continue
            rilinks_by_radio[rk].append(RiLinkConfig(
                link_number=str(row["RiLinkId"]).strip(),
                ri_port_ref1=str(row["riPortRef1"]).strip(),
                ri_port_ref2=str(row["riPortRef2"]).strip(),
                site=str(row["Site"]).strip(),
            ))

        # Per-radio checks
        site_tech_map = {site1.strip(): site1_tech, **({site2.strip(): site2_tech} if (site2_enable and site2.strip()) else {})}
        for _, row in r.iterrows():
            rk = row["RadioKey"]
            model = row["RadioModel"]
            mode = row["RadioMode"]

            if rk not in map_by_radio:
                errors.append(f"Radio {rk}: no mapping rows.")
                continue
            if not params_by_radio.get(rk):
                errors.append(f"Radio {rk}: no carrier rows.")

            # mapping ports must be active
            act = active_ports(model, mode)
            for br, port in map_by_radio[rk].items():
                if port not in act:
                    errors.append(f"Radio {rk}: Branch {br} uses inactive port {port} for {model}/{mode}.")

            # carrier branches must exist in mapping
            mapped = set(map_by_radio[rk].keys())
            missing = sorted({b for p in params_by_radio.get(rk, []) for b in p.rfbs if b not in mapped})
            if missing:
                errors.append(f"Radio {rk}: missing mapping for branches {missing}.")            # band validity check
            allowed_bands = set(RADIO_LIBRARY[model].get('bands', []))
            bad_bands = sorted({pp.band for pp in params_by_radio.get(rk, []) if pp.band not in allowed_bands})
            if bad_bands:
                errors.append(f"Radio {rk}: Band(s) {bad_bands} not supported by model {model}. Allowed: {sorted(allowed_bands)}.")

            # mode/band validation
            err = validate_per_band_mode_rules(model, mode, params_by_radio.get(rk, []))
            if err:
                errors.append(f"Radio {rk}: {err}")

            # carriers span sites requires CreateInBothSites
            used_sites = sorted({p.site for p in params_by_radio.get(rk, [])})

            # tech validation: when node tech is LTE+NR, each carrier should specify CarrierTech
            for sname in used_sites:
                node_t = site_tech_map.get(sname, 'LTE')
                if str(node_t).upper() == 'LTE+NR':
                    missing_t = [pp.sector_carrier_id for pp in params_by_radio.get(rk, []) if pp.site == sname and str(getattr(pp, 'tech', '') or '').strip().upper() not in ('LTE','NR')]
                    if missing_t:
                        errors.append(f"Radio {rk}: Site {sname} is LTE+NR but CarrierTech missing for SectorCarrierId(s) {missing_t}.")

            if len(used_sites) > 1 and (not bool(row.get("CreateInBothSites", False))):
                errors.append(f"Radio {rk}: carriers span sites {used_sites} but CreateInBothSites is FALSE.")

            # RX>TX requires mapping size
            rx, tx = rx_tx_for(model, mode)
            if rx > tx and len(map_by_radio[rk]) < rx:
                errors.append(f"Radio {rk}: mode {mode} requires {rx} RX branches but mapping has {len(map_by_radio[rk])}.")

        if errors:
            st.error("Fix the following issues before generating:")
            for e in errors:
                st.write(f"- {e}")
            return

        # Build SectorConfig list
        sectors: List[SectorConfig] = []
        sector_idx = 1
        for _, row in r.iterrows():
            rk = row["RadioKey"]
            sectors.append(SectorConfig(
                sector_number=sector_idx,
                aug_group=row["AUG"],
                rru_base=row["RRUBase"],
                radio_model=row["RadioModel"],
                radio_mode=row["RadioMode"],
                shared_sector_equipment=bool(row.get("SharedSE", False)),
                params=params_by_radio[rk],
                rilinks=rilinks_by_radio.get(rk, []),
                branch_port_map=map_by_radio[rk],
                radio_site=row["RadioSite"],
                create_in_both_sites=bool(row.get("CreateInBothSites", False)),
            ))
            sector_idx += 1

        cfg = WizardConfig(
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            sitename=site1.strip(),
            sitename2=site2.strip() if site2_enable and site2.strip() else None,
            sectors=sectors,
            vswr_enable=vswr_enable,
            vswr_ports=vswr_ports,
            vswr_sensitivity=vswr_sensitivity,
            site_tech={site1.strip(): site1_tech, **({site2.strip(): site2_tech} if (site2_enable and site2.strip()) else {})},
        )

        bulk1 = generate_bulk_for_site(cfg, cfg.sitename)
        bulk2 = generate_bulk_for_site(cfg, cfg.sitename2) if cfg.sitename2 else ""
        json_text = json.dumps(asdict(cfg), indent=2)

        st.session_state.generated = True
        st.session_state.bulk_site1 = bulk1
        st.session_state.bulk_site2 = bulk2
        st.session_state.json_text = json_text

        out_dir = st.session_state.output_dir.strip()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if out_dir:
            try:
                out_path = Path(out_dir)
                out_path.mkdir(parents=True, exist_ok=True)
                (out_path / f"{cfg.sitename}_{stamp}_Radio_CLI_Script.txt").write_text(bulk1, encoding="utf-8")
                if bulk2 and cfg.sitename2:
                    (out_path / f"{cfg.sitename2}_{stamp}_Radio_CLI_Script.txt").write_text(bulk2, encoding="utf-8")
                st.success(f"Saved generated files to: {out_path}")
            except Exception as e:
                st.warning(f"Could not save to folder path: {e}. Use downloads below.")

    if st.session_state.generated:
        st.subheader("Generated Output")
        tabs = ["Site-1", "JSON"]
        if site2_enable and site2.strip():
            tabs.insert(1, "Site-2")
        tab_objs = st.tabs(tabs)

        with tab_objs[0]:
            st.code(st.session_state.bulk_site1, language="text")
            st.download_button(
                "Download Site-1 CLI Script",
                st.session_state.bulk_site1,
                file_name=f"{site1.strip()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_Radio_CLI_Script.txt",
                mime="text/plain",
            )

        idx = 1
        if site2_enable and site2.strip():
            with tab_objs[1]:
                st.code(st.session_state.bulk_site2, language="text")
                st.download_button(
                    "Download Site-2 CLI Script",
                    st.session_state.bulk_site2,
                    file_name=f"{site2.strip()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_Radio_CLI_Script.txt",
                    mime="text/plain",
                )
            idx = 2

        with tab_objs[idx]:
            st.code(st.session_state.json_text, language="json")
            st.download_button("Download JSON", st.session_state.json_text, file_name="inputs.json", mime="application/json")

# ---------------------------
# RET SCRIPTING APP (merged from RET_UI_v6.py)
# ---------------------------
def ret_render():
    render_top_banner()
    import streamlit as st
    import pandas as pd
    import io
    import zipfile
    import re
    from collections import defaultdict
    from typing import Dict, Tuple, List, Any


    import uuid
    if "_session_guid" not in st.session_state:
        st.session_state["_session_guid"] = uuid.uuid4().hex

    st.sidebar.write("Session GUID:", st.session_state["_session_guid"])
    st.session_state["_reruns"] = st.session_state.get("_reruns", 0) + 1
    st.sidebar.write("Reruns:", st.session_state["_reruns"])
    # (moved to Home_merged_supabase_auth.py) st.set_page_config(...) 
    # ============================================================
    # HARD-CODED ANTENNA MODEL DATABASE
    # ============================================================
    HARDCODED_DB = [
        {"AntennaModel": "NNH4-45A-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": True},
    	{"AntennaModel": "NNH4-45B-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4-65A-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": True},
    	{"AntennaModel": "NNH4-65A-R6H4", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4-65B-R3-UPM", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4-65B-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": True},
    	{"AntennaModel": "NNH4-65B-R6H4", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4-65B-R8D", "NoOfSubunits": 8, "SubunitLabelling": "R1,R2,R3,R4,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4-65C-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": True},
    	{"AntennaModel": "NNH4-65C-R6H4", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4-65C-R6-HG", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4-65C-R6-UPM", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": True},
    	{"AntennaModel": "NNH4-65C-R6-V3", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": True},
    	{"AntennaModel": "NNH4-65C-R6-V4", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4-65C-R8D", "NoOfSubunits": 8, "SubunitLabelling": "R1,R2,R3,R4,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4-65D-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": True},
    	{"AntennaModel": "NNH4-85B-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "NNH4S4-65C-R7", "NoOfSubunits": 7, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4,P1", "SupportsPairing": False},
    	{"AntennaModel": "NNHH-45A-R4", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "NNHH-45B-R4", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "NNHH-45C-R4", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "NNHH-65A-R4", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "NNHH-65A-R4-UPM", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "NNHH-65B-R2-UPM", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "NNHH-65B-R4", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "NNHH-65C-R2-UPM", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "NNHH-65C-R4", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "NNHHS4-65A-R5", "NoOfSubunits": 5, "SubunitLabelling": "R1,R2,Y1,Y2,P1", "SupportsPairing": False},
    	{"AntennaModel": "NNHHS4-65B-R5", "NoOfSubunits": 5, "SubunitLabelling": "R1,R2,Y1,Y2,P1", "SupportsPairing": False},
    	{"AntennaModel": "NNHHS4-65C-R5", "NoOfSubunits": 5, "SubunitLabelling": "R1,R2,Y1,Y2,P1", "SupportsPairing": False},
    	{"AntennaModel": "OCT4-1A1G2U-RD85", "NoOfSubunits": 5, "SubunitLabelling": "R1,Y1,P1,P2", "SupportsPairing": False},
    	{"AntennaModel": "OPA65R-BU4B", "NoOfSubunits": 2, "SubunitLabelling": "R1,YL-YR", "SupportsPairing": False},
    	{"AntennaModel": "OPA65R-BU4DA-K", "NoOfSubunits": 2, "SubunitLabelling": "RL1-RR1,YL-YR", "SupportsPairing": False},
    	{"AntennaModel": "OPA65R-BU6DA-K", "NoOfSubunits": 2, "SubunitLabelling": "RL1-RR1,YL-YR", "SupportsPairing": False},
    	{"AntennaModel": "OPA65R-BU8B", "NoOfSubunits": 2, "SubunitLabelling": "R1,YL-YR", "SupportsPairing": False},
    	{"AntennaModel": "OPA65R-BU8DA-K", "NoOfSubunits": 2, "SubunitLabelling": "RL1-RR1,YL-YR", "SupportsPairing": False},
    	{"AntennaModel": "OPA-65R-LCUU-H4", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,YL,YR", "SupportsPairing": False},
    	{"AntennaModel": "OPA-65R-LCUU-H6", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,YL,YR", "SupportsPairing": False},
    	{"AntennaModel": "OPA-65R-LCUU-H8", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,YL,YR", "SupportsPairing": False},
    	{"AntennaModel": "QD4616-3", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1-Y2,Y3-Y4", "SupportsPairing": True},
        {"AntennaModel": "QD4616-7", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1-Y2,Y3-Y4", "SupportsPairing": False},
    	{"AntennaModel": "QD6612-3D", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1-Y2,Y3-Y4", "SupportsPairing": True},
    	{"AntennaModel": "QD6616-3", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1-Y2,Y3-Y4", "SupportsPairing": True},
    	{"AntennaModel": "QD6616-7", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1-Y2,Y3-Y4", "SupportsPairing": False},
    	{"AntennaModel": "QD66512-3D", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1-Y2,Y3-Y4", "SupportsPairing": True},
    	{"AntennaModel": "QD6658-3D", "NoOfSubunits": 4, "SubunitLabelling": "R1-R3,R2-R4,Y1-Y2,Y3-Y4", "SupportsPairing": False},
    	{"AntennaModel": "QD668-3D", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1,Y2", "SupportsPairing": True},
    	{"AntennaModel": "QD8612-3D", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1-Y2,Y3-Y4", "SupportsPairing": True},
    	{"AntennaModel": "QD8616-7", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1-Y2,Y3-Y4", "SupportsPairing": False},
    	{"AntennaModel": "QD868-3D", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,R3,R4,Y1,Y2", "SupportsPairing": True},
    	{"AntennaModel": "QS46512-2", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1-Y2,B1-B2", "SupportsPairing": False},
    	{"AntennaModel": "QS66510-6", "NoOfSubunits": 3, "SubunitLabelling": "R1,B1-B2,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "QS66512-2", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1-Y2,B1-B2", "SupportsPairing": False},
    	{"AntennaModel": "QS66512-6", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1-Y2,B1-B2", "SupportsPairing": False},
    	{"AntennaModel": "QS6656-3", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "QS6658-3e", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "QS6658-5", "NoOfSubunits": 3, "SubunitLabelling": "R1,R2,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "QS6658-7", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "QS86512-2", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1-Y2,B1-B2", "SupportsPairing": False},
    	{"AntennaModel": "QS8658-3e", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "QS8658-7", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "QW6612-5C", "NoOfSubunits": 2, "SubunitLabelling": "Y1-Y2,P1-P2", "SupportsPairing": False},
    	{"AntennaModel": "RR2HH-6533D-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "RR2VV-6533B-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "RR2VV-6533D-R6", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "RV4PX310R-V2", "NoOfSubunits": 5, "SubunitLabelling": "R1,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "S4-90M-R1-V5", "NoOfSubunits": 1, "SubunitLabelling": "P1", "SupportsPairing": False},
    	{"AntennaModel": "SBJAH4-1D65B-DL", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y3,Y2-Y4", "SupportsPairing": False},
    	{"AntennaModel": "SBJAH4-1D65C-DL", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y3,Y2-Y4", "SupportsPairing": False},
    	{"AntennaModel": "SBJAHH-1D65B-DL", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBJAHH-1D65C-DL", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNH-1D4545A", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNH-1D6565A", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNH-1D6565B", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1-Y2", "SupportsPairing": False},
        {"AntennaModel": "SBNH-1D6565C", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D45A", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D45B", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D45C", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D65A", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D65B", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D65C", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D85A", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D85B", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D85C", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "SBNHH-1D85D", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "TPA33R-BU8C", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y2,Y3-Y4", "SupportsPairing": False},
    	{"AntennaModel": "TPA45R-BU6B", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y3,Y2-Y4", "SupportsPairing": False},
    	{"AntennaModel": "TPA45R-BU8BB-K", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y3,Y2-Y4", "SupportsPairing": False},
    	{"AntennaModel": "TPA-45R-KU6AA-K", "NoOfSubunits": 3, "SubunitLabelling": "RT-RB,YTL-YTR,YBL-YBR", "SupportsPairing": False},
    	{"AntennaModel": "TPA45R-KU8A", "NoOfSubunits": 3, "SubunitLabelling": "RT-RB,YTL-YTR,YBL-YBR", "SupportsPairing": False},
    	{"AntennaModel": "TPA65R-BU4DA", "NoOfSubunits": 3, "SubunitLabelling": "RL1-RR1,YL-YCL,YCR-YR", "SupportsPairing": False},
    	{"AntennaModel": "TPA65R-BU6AA-K", "NoOfSubunits": 3, "SubunitLabelling": "RL1-RR1,YL-YCL,YCR-YR", "SupportsPairing": False},
    	{"AntennaModel": "TPA65R-BU6DA", "NoOfSubunits": 3, "SubunitLabelling": "RL1-RR1,YL-YCL,YCR-YR", "SupportsPairing": False},
    	{"AntennaModel": "TPA-65R-BU8A", "NoOfSubunits": 3, "SubunitLabelling": "RL1-RR1,YL-YCL,YCR-YR", "SupportsPairing": False},
    	{"AntennaModel": "TPA65R-BU8D", "NoOfSubunits": 3, "SubunitLabelling": "RL1-RR1,YL-YCL,YCR-YR", "SupportsPairing": False},
    	{"AntennaModel": "TPA65R-BU8DA", "NoOfSubunits": 3, "SubunitLabelling": "RL1-RR1,YL-YCL,YCR-YR", "SupportsPairing": False},
    	{"AntennaModel": "TPA65R-BU8Dv2", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y2,Y3-Y4", "SupportsPairing": False},
    	{"AntennaModel": "TPA65R-BU8GB-K", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y2,Y3-Y4", "SupportsPairing": False},
    	{"AntennaModel": "TPA-65R-LCUUUU-H6", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,YL,YR", "SupportsPairing": False},
    	{"AntennaModel": "TPA-65R-LCUUUU-H8", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,YTL-YTR,YBL-YBR", "SupportsPairing": False},
    	{"AntennaModel": "XXQLH-654L4H6-iVT", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
    	{"AntennaModel": "XXQLH-654L4H8-iVT", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1-Y2", "SupportsPairing": False},
    	{"AntennaModel": "XXQLH-654L8H6-iVT", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "XXQLH-654L8H6-iVT", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
    	{"AntennaModel": "120706", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "120716", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "120726", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "120816", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "80010722", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "80010766", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "80010865", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "80010866", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "800372965", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "800372991", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "840370799", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "12HBSAR-BU6NAA-K", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y3,Y2-Y4", "SupportsPairing": True},
        {"AntennaModel": "2NN2HH-33B-R4", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y3,Y2-Y4", "SupportsPairing": True},
        {"AntennaModel": "2NN2HH-33C-R4", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y3,Y2-Y4", "SupportsPairing": True},
        {"AntennaModel": "742-264", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "800 10864 K", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "80010735V01", "NoOfSubunits": 1, "SubunitLabelling": "R1", "SupportsPairing": False},
        {"AntennaModel": "80010735V01", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "800372965", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "800372965", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "AM-X-CD-16-65-00T-RET", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "AM-X-CD-17-65-00T-RET", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "AM-X-CD-17-65-00T-RET", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "BSA33R-BU6BB-K", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "BSA33R-BU8AA-K", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "BSA33R-BU8BB-K", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "BSA33R-BU8BB-K", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "BSA-M65R-BUU-H6", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-UBTLBHH6517-21-21", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-BTLBHH/6516/20/20/A15_RET", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-BTLBHH-6516-20-20-A15_RET", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-BTLBHH-6518-20-20", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-BTLBHH-6518-20-20-A15", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-BTLBHH-6518-20-20-A15_RET", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-BTLBHH-6518-20-20-A15_RET", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-UBTLBHH6517-21-21", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-UBTLBLBHHHHP/6518/18/22/22/22/22", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "CMA-UBTMLBMLBHH-6516-16-21-21", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-UBTULBHHP/6517/21/21", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-UBTULBULBHH-6517-17-21-21", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-UBTULBULBHHP/6516/16/21/21", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-UBTULBULBHHP/6517/17/21/21", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CMA-UBTULBULBHHP-6517-17-21-21", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "CUUX063X19x00", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "DBXLH-8585A", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "DBXNH-6565B", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "DEC4-1A2G2U-RC65", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1-Y2,P1-P2", "SupportsPairing": False},
        {"AntennaModel": "DMP65R-BU4D", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,R3-R4,Y1-Y2", "SupportsPairing": False},
        {"AntennaModel": "DMP65R-BU4EA-K", "NoOfSubunits": 4, "SubunitLabelling": "R1-R2,R3-R4,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "DMP65R-BU6D", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,R3-R4,Y1-Y2", "SupportsPairing": False},
        {"AntennaModel": "DMP65R-BU8EA-K", "NoOfSubunits": 4, "SubunitLabelling": "R1-R2,R3-R4,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "DPA65R-BU6DB-K", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,R3,Y1-Y2", "SupportsPairing": False},
        {"AntennaModel": "DPA-65R-BUUUU-H8B", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "EPBQ-652L8H8", "NoOfSubunits": 4, "SubunitLabelling": "Y3-Y4,Y1-Y2,R1-R2", "SupportsPairing": False},
        {"AntennaModel": "EPBQ-654L4H6-L2-EPI", "NoOfSubunits": 4, "SubunitLabelling": "Y3-Y4,Y1-Y2,R1-R2", "SupportsPairing": False},
        {"AntennaModel": "EPBQ-654L4H8-L2-EPI", "NoOfSubunits": 4, "SubunitLabelling": "Y3-Y4,Y1-Y2,R1-R2", "SupportsPairing": False},
        {"AntennaModel": "EPBQ-654L8H6-B", "NoOfSubunits": 4, "SubunitLabelling": "Y3-Y4,Y1-Y2,R1-R2", "SupportsPairing": False},
        {"AntennaModel": "EPBQ-654L8H6-L2", "NoOfSubunits": 4, "SubunitLabelling": "Y3-Y4,Y1-Y2,R1-R2", "SupportsPairing": False},
        {"AntennaModel": "EPBQ-654L8H8-B", "NoOfSubunits": 4, "SubunitLabelling": "Y3-Y4,Y1-Y2,R1-R2", "SupportsPairing": False},
        {"AntennaModel": "EPBQ-654L8H8-HG", "NoOfSubunits": 4, "SubunitLabelling": "Y3-Y4,Y1-Y2,R1-R2", "SupportsPairing": False},
        {"AntennaModel": "EPBQ-654L8H8-L2", "NoOfSubunits": 4, "SubunitLabelling": "Y3-Y4,Y1-Y2,R1-R2", "SupportsPairing": False},
        {"AntennaModel": "ET-X-UW-70-16-70-18-IR-AT", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "ET-X-UW-68-14-65-18-IR-AT", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "FFV4-65B-R3-HG", "NoOfSubunits": 3, "SubunitLabelling": "R1-R2,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "FFVV-65B-R2-HG", "NoOfSubunits": 2, "SubunitLabelling": "R1,Y1", "SupportsPairing": False},
        {"AntennaModel": "FPA65R-BU6DB-K", "NoOfSubunits": 4, "SubunitLabelling": "R1-R2,R3,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "FPA65R-BU8DB-K", "NoOfSubunits": 4, "SubunitLabelling": "R1-R2,R3,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "HBSA33R-KU6AA-K", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "HPA-33R-BUU-H6", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "HPA65R-BU4A", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "HPA65R-BU6A", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "HPA65R-BU6AA", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "HPA65R-BU8A", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "HPA-65R-BUU-H4", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "HPA-65R-BUU-H6", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "HPA-65R-BUU-H8", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "JAH4-65B-R4", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1-Y3,Y2-Y4", "SupportsPairing": True},
        {"AntennaModel": "JAH4-65C-R4", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1-Y3,Y2-Y4", "SupportsPairing": True},
        {"AntennaModel": "JAHH-65A-R3B", "NoOfSubunits": 3, "SubunitLabelling": "R1,R2,Y1-Y2", "SupportsPairing": False},
        {"AntennaModel": "JAHH-65B-R3B", "NoOfSubunits": 3, "SubunitLabelling": "R1,R2,Y1-Y2", "SupportsPairing": False},
        {"AntennaModel": "JAHH-65B-R3B-V3", "NoOfSubunits": 3, "SubunitLabelling": "R1,R2,Y1", "SupportsPairing": False},
        {"AntennaModel": "JAHH-65C-R3B", "NoOfSubunits": 3, "SubunitLabelling": "R1,R2,Y1-Y2", "SupportsPairing": False},
        {"AntennaModel": "JAHH-65B-R3B-V3", "NoOfSubunits": 3, "SubunitLabelling": "R1,R2,Y1-Y2", "SupportsPairing": False},
        {"AntennaModel": "JAHH-65B-R3B-V3", "NoOfSubunits": 3, "SubunitLabelling": "R1,R2,Y1-Y2", "SupportsPairing": False},
        {"AntennaModel": "JJAAH4-65A-R6", "NoOfSubunits": 4, "SubunitLabelling": "R1-R2,R3-R4,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "JJAAH4-65B-R6", "NoOfSubunits": 4, "SubunitLabelling": "R1-R2,R3-R4,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "JJAAH4-65C-R6", "NoOfSubunits": 4, "SubunitLabelling": "R1-R2,R3-R4,Y1-Y2,Y3-Y4", "SupportsPairing": False},
        {"AntennaModel": "KRE 101 2487/1K", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "KRE 101 2526/1K", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "KRE 101 2527/1K", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "KRE 101 2527/1K", "NoOfSubunits": 6, "SubunitLabelling": "R1,R2,Y1,Y2,Y3,Y4", "SupportsPairing": False},
        {"AntennaModel": "KRE 101 2586/1K", "NoOfSubunits": 4, "SubunitLabelling": "R1,R2,Y1,Y2", "SupportsPairing": False},
        {"AntennaModel": "KVVSS-65A-R3", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1-Y2,P1-P2", "SupportsPairing": False},
        {"AntennaModel": "KVVSS-65A-R3", "NoOfSubunits": 3, "SubunitLabelling": "R1,Y1-Y2,P1-P2", "SupportsPairing": False},
        ]
    DB_DF = pd.DataFrame(HARDCODED_DB)

    # ============================================================
    # CONSTANTS
    # ============================================================
    AUG_MAP = {"ALPHA": 1, "BETA": 2, "GAMMA": 3, "DELTA": 4, "EPSILON": 5, "FOXTROT": 6}
    AUG_FACING = {"ALPHA": "A", "BETA": "B", "GAMMA": "C", "DELTA": "D", "EPSILON": "E", "FOXTROT": "F"}
    RET_TYPES = ["S-RET", "M-RET"]

    TECH_CODES = {
        "F": "License Restricted",
        "J": "LTE + 5G NR",
        "L": "LTE",
        "N": "None",
        "M": "Exception",
        "R": "5G NR",
    }
    TECH_OPTIONS = list(TECH_CODES.keys())

    # BandCode -> base bands
    BANDCODE_TO_BANDS = {
        "1": ["MMWAVE"],
        "2": ["AWS"],
        "3": ["WCS"],
        "4": ["CBAND", "DOD"],
        "5": ["DOD"],
        "6": ["B66"],
        "7": ["L700"],
        "8": ["850"],
        "9": ["PCS"],
        "A": ["AWS", "B66"],
        "B": ["PCS", "B66"],
        "C": ["PCS", "B66", "WCS"],
        "D": ["PCS", "AWS"],
        "E": ["WCS", "B66"],
        "F": ["PCS", "WCS"],
        "G": ["PCS", "AWS", "B66"],
        "H": ["AWS", "WCS"],
        "I": ["PCS", "WCS", "B66"],
        "J": ["PCS", "AWS", "WCS"],
        "K": ["L700", "850"],
        "L": ["L700", "B29"],
        "M": ["PCS", "AWS", "B66", "WCS"],
        "O": ["PCS", "AWS", "B66", "WCS", "L700", "B14"],
        "P": ["B14"],
        "Q": ["B29"],
        "R": ["L700", "B14", "850"],
        "S": ["L700", "B29", "850"],
        "T": ["L700", "B14", "B29"],
        "U": ["L700", "B29", "B14", "850"],
        "V": ["CBAND"],
        "W": ["B29", "B14"],
        "X": ["L700", "B14"],
        "Y": ["B29", "850"],
        "Z": ["B14", "850"],
        "N": [],
    }

    BANDCODE_HELP = {
        "1": "mmWave",
        "2": "AWS",
        "3": "WCS",
        "4": "C-band & DoD",
        "5": "DoD",
        "6": "B66",
        "7": "L700",
        "8": "850",
        "9": "PCS",
        "A": "AWS + B66",
        "B": "PCS + B66",
        "C": "PCS + B66 + WCS",
        "D": "PCS + AWS",
        "E": "WCS + B66",
        "F": "PCS + WCS",
        "G": "PCS + AWS + B66",
        "H": "AWS + WCS",
        "I": "PCS + WCS + B66",
        "J": "PCS + AWS + WCS",
        "K": "L700 + 850",
        "L": "L700 + B29",
        "M": "PCS + AWS + B66 + WCS",
        "O": "PCS + AWS + B66 + WCS + L700 + B14",
        "P": "B14",
        "Q": "B29",
        "R": "L700 + B14 + 850",
        "S": "L700 + B29 + 850",
        "T": "L700 + B14 + B29",
        "U": "L700 + B29 + B14 + 850",
        "V": "C-band",
        "W": "B29 + B14",
        "X": "L700 + B14",
        "Y": "B29 + 850",
        "Z": "B14 + 850",
        "N": "Not Used",
    }

    BANDCODE_OPTIONS = list(BANDCODE_TO_BANDS.keys())
    BAND_DISPLAY = {k: f"{BANDCODE_HELP.get(k,k)} ({k})" for k in BANDCODE_OPTIONS}
    TECH_DISPLAY = {k: f"{TECH_CODES.get(k,k)} ({k})" for k in TECH_OPTIONS}
    BAND_DISPLAY_OPTIONS = [BAND_DISPLAY[k] for k in BANDCODE_OPTIONS]
    TECH_DISPLAY_OPTIONS = [TECH_DISPLAY[k] for k in TECH_OPTIONS]


    def decode_code(display: str) -> str:
        s = (display or "").strip()
        if s.endswith(")") and "(" in s:
            return s.rsplit("(", 1)[1].rstrip(")").strip()
        return s


    # ============================================================
    # CELL DUMP PARSER
    # ============================================================
    LTE_RE = re.compile(r"^(?P<prefix>[A-Z0-9]+)_(?P<banddigit>\d)(?P<facing>[A-F])_(?P<car>\d+)(?:_(?P<extra>[A-Z]))?$", re.I)
    NR_RE  = re.compile(r"^NRCell(?P<node>DU|CU)=(?P<prefix>[A-Z0-9]+)_(?P<ncode>N\d{3})(?P<facing>[A-F])_(?P<idx>\d+)$", re.I)


    def classify_lte(banddigit: str, extra: str | None, car: str | None) -> str:
        """LTE classification.

        Change requested: treat _7*_3_F as B14 (instead of F_NET).
        """
        banddigit = str(banddigit)
        extra = (extra or "").upper().strip()
        car = str(car or "").strip()

        if banddigit == "2":
            return "AWS"
        if banddigit == "6":
            return "B66"
        if banddigit == "9":
            return "PCS"
        if banddigit == "3":
            return "WCS"
        if banddigit == "7":
            if extra == "E":
                return "B29"
            if extra == "F":
                return "B14"  # requested mapping
            return "L700"
        return "UNKNOWN"


    def classify_nr(ncode: str, idx: str) -> str:
        ncode = (ncode or "").upper()
        idx = str(idx or "")
        if ncode == "N066":
            return "AWS"
        if ncode == "N002":
            return "PCS"
        if ncode == "N005":
            return "850"
        if ncode == "N077":
            return "CBAND" if idx == "1" else ("DOD" if idx == "2" else "CBAND")
        return "UNKNOWN"


    def parse_dump(text: str) -> pd.DataFrame:
        rows = []
        for raw in (text or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            if " - " in line:
                cell, _ = line.split(" - ", 1)
            else:
                cell = line
            cell = cell.strip()

            rat = "UNKNOWN"
            node_key = ""
            facing = ""
            carrier = ""
            band = "UNKNOWN"

            m_nr = NR_RE.match(cell)
            m_lte = LTE_RE.match(cell)

            if m_nr:
                rat = "NR"
                node_key = m_nr.group("prefix")
                facing = m_nr.group("facing").upper()
                ncode = m_nr.group("ncode").upper()
                idx = m_nr.group("idx")
                carrier = idx
                band = classify_nr(ncode, idx)
            elif m_lte:
                rat = "LTE"
                node_key = m_lte.group("prefix")
                facing = m_lte.group("facing").upper()
                banddigit = m_lte.group("banddigit")
                carrier = m_lte.group("car")
                extra = m_lte.group("extra")
                band = classify_lte(banddigit, extra, carrier)

            rows.append({
                "raw": raw,
                "cell": cell,
                "rat": rat,
                "node": node_key,
                "facing": facing,
                "band": band,
                "carrier": str(carrier),
            })

        return pd.DataFrame(rows)


    # ============================================================
    # CELL INDEX + AWS CARRIER MAPPING
    # ============================================================

    def build_cell_index(cell_df: pd.DataFrame, aws_carrier_band: Dict[Tuple[str, str, str], str]) -> Dict[Tuple[str, str, str, str], List[str]]:
        idx = defaultdict(list)
        for _, r in cell_df.iterrows():
            cell = r.get("cell")
            rat = r.get("rat")
            node = r.get("node")
            facing = r.get("facing")
            band = r.get("band")
            carrier = r.get("carrier")

            if rat == "LTE" and band == "AWS" and node and facing and carrier:
                band_eff = aws_carrier_band.get((node, facing, str(carrier)), "AWS")
            else:
                band_eff = band

            if node and rat and band_eff and facing:
                idx[(node, rat, band_eff, facing)].append(cell)

        for k in list(idx.keys()):
            idx[k] = sorted(idx[k])

        return dict(idx)


    def pick_cells(cell_index: Dict[Tuple[str, str, str, str], List[str]], rat: str, band: str, facing: str, preferred_node: str | None = None) -> Tuple[str, List[str]]:
        pref = (preferred_node or "").strip()
        if pref:
            cells = cell_index.get((pref, rat, band, facing), [])
            if cells:
                return pref, list(cells)

        for (node, r, b, f), cells in cell_index.items():
            if r == rat and b == band and f == facing and cells:
                return node, list(cells)

        return "", []


    def pick_one(cell_index: Dict[Tuple[str, str, str, str], List[str]], rat: str, band: str, facing: str, preferred_node: str | None = None) -> Tuple[str, str]:
        node, cells = pick_cells(cell_index, rat, band, facing, preferred_node)
        return node, (cells[0] if cells else "")


    # ============================================================
    # LABEL HELPERS
    # ============================================================

    def pad_usid(usid: str) -> str:
        digits = "".join(ch for ch in (usid or "") if ch.isdigit())
        return digits.zfill(6)[:6] if digits else ""


    def y_group(subunit_label: str) -> str:
        s = str(subunit_label).upper().strip()
        return s if s in {"Y1", "Y2", "Y3", "Y4"} else ""


    def join_nonempty(parts: List[str], sep: str = ";") -> str:
        return sep.join([p for p in parts if p])


    def parse_cell_name_for_label(cell_name: str) -> str:
        if not cell_name:
            return ""
        s = str(cell_name).strip()
        return s.split("=", 1)[1] if "=" in s else s


    def join_cells_for_label(cells: List[str]) -> str:
        return join_nonempty([parse_cell_name_for_label(c) for c in cells])


    def normalize_rxtx(rx_tx: str) -> str:
        s = (rx_tx or "").lower().replace("*", "x").replace(" ", "")
        return "8x4" if s == "8x4" else "4x4"


    def cell_part_aws_pcs(aws_lte_all: str, pcs_lte_all: str, aws_5g: str, pcs_5g: str,
                          include_5g: bool, rx_tx: str, pairing: str, y: str) -> str:
        aws_lte_all = (aws_lte_all or "").strip()
        pcs_lte_all = (pcs_lte_all or "").strip()
        aws_5g = parse_cell_name_for_label(aws_5g)
        pcs_5g = parse_cell_name_for_label(pcs_5g)

        aws_parts = [aws_lte_all]
        pcs_parts = [pcs_lte_all]
        if include_5g:
            aws_parts.append(aws_5g)
            pcs_parts.append(pcs_5g)

        left_aws = join_nonempty([p for p in aws_parts if p])
        left_pcs = join_nonempty([p for p in pcs_parts if p])

        if not left_aws and not left_pcs:
            return ""
        if left_aws and not left_pcs:
            return left_aws
        if left_pcs and not left_aws:
            return left_pcs

        rx = normalize_rxtx(rx_tx)
        pairing_yes = str(pairing).strip().upper() == "YES"
        y = (y or "").upper().strip()

        if rx != "8x4":
            return join_nonempty([left_aws, left_pcs])

        if pairing_yes:
            group1, group2 = {"Y1", "Y3"}, {"Y2", "Y4"}
        else:
            group1, group2 = {"Y1", "Y2"}, {"Y3", "Y4"}

        if y in group1:
            return join_nonempty([left_pcs, "RX", left_aws])
        if y in group2:
            return join_nonempty([left_aws, "RX", left_pcs])

        return join_nonempty([left_aws, left_pcs])


    def build_user_label(usid6: str, facing: str, position: str, band_code: str, tech_code: str, cell_name_part: str) -> str:
        if not usid6 or not facing or position is None:
            return ""
        return f"{usid6}{facing}--{position}{band_code}{tech_code}__{cell_name_part}"


    # ============================================================
    # BASIC/RET/SUBUNIT GENERATION
    # ============================================================




    def build_basic_input(site_id: str, groups: List[Dict[str, Any]]) -> pd.DataFrame:
        """Step 1: Basic Input.

        Option-A Azimuth:
        - Capture azimuth once per AUG group and apply it to all antennas in that AUG.
        """
        rows = []
        for g in groups:
            aug_name = g["aug_name"].upper()
            aug_no = AUG_MAP[aug_name]
            az = g.get("azimuth", "")
            for ant_no in range(1, g["ant_count"] + 1):
                rows.append({
                    "Site ID": site_id,
                    "AUG Name": aug_name,
                    "AUG Number": aug_no,
                    "Antenna Number": ant_no,
                    "Azimuth": az,
                })
        return pd.DataFrame(rows)

    def create_ret_input(basic_df: pd.DataFrame) -> pd.DataFrame:
        ret_df = basic_df.copy()
        add_cols = [
            "Position", "Antenna Model", "RET TYPE", "Azimuth",
            "Controlling Radio", "UID", "Tilt (default)",
            "Node_LTE", "Node_NR_DU", "Node_NR_CU",
        ]
        for c in add_cols:
            if c not in ret_df.columns:
                ret_df[c] = ""
        return ret_df



    def supports_pairing_for_model(model: str) -> bool:
        hit = DB_DF[DB_DF["AntennaModel"].astype(str).str.strip() == str(model).strip()]
        return bool(hit.iloc[0].get("SupportsPairing", False)) if not hit.empty else False



    def generate_subunit_input(ret_df: pd.DataFrame, db_df: pd.DataFrame) -> pd.DataFrame:
        model_to_labels = {}
        for _, r in db_df.iterrows():
            model_to_labels[str(r["AntennaModel"]).strip()] = [
                x.strip() for x in str(r.get("SubunitLabelling", "")).split(",") if x.strip()
            ]

        cols = [
            "Site ID", "AUG Name", "Facing",
            "Node_LTE", "Node_NR_DU", "Node_NR_CU",
            "AUG No", "Ant No",
            "RET TYPE", "Antenna Model",
            "ANU No", "RU", "UID", "RSU No",
            "Tilt", "Bearing",
            "User Label",
            "RU_effective", "Context_effective",
            "AU Ref", "ASU Ref", "Subunit Label",
        ]

        out = []
        for _, r in ret_df.iterrows():
            model = str(r.get("Antenna Model", "")).strip()
            ret_type = str(r.get("RET TYPE", "")).strip()
            pos = r.get("Position", "")
            if not model or not ret_type or pos == "":
                continue
            try:
                position = int(pos)
            except Exception:
                continue

            labels = model_to_labels.get(model, [])
            au_ref = position
            anu_start = position * 10 + 1

            azimuth = r.get("Azimuth", "")
            try:
                bearing_val = int(round(float(azimuth) * 10))
            except Exception:
                bearing_val = ""

            aug_name = str(r["AUG Name"]).upper()
            facing = AUG_FACING.get(aug_name, "")

            node_lte = str(r.get("Node_LTE", "")).strip()
            node_du = str(r.get("Node_NR_DU", "")).strip()
            node_cu = str(r.get("Node_NR_CU", "")).strip()

            site_id = str(r.get("Site ID", "")).strip()

            for idx, label in enumerate(labels):
                row = {c: "" for c in cols}
                row["Site ID"] = site_id
                row["AUG Name"] = aug_name
                row["Facing"] = facing
                row["Node_LTE"] = node_lte
                row["Node_NR_DU"] = node_du
                row["Node_NR_CU"] = node_cu
                row["AUG No"] = r["AUG Number"]
                row["Ant No"] = r["Antenna Number"]
                row["RET TYPE"] = ret_type
                row["Antenna Model"] = model
                row["RU"] = str(r.get("Controlling Radio", "")).strip()
                row["AU Ref"] = au_ref
                row["ASU Ref"] = idx + 1
                row["Subunit Label"] = label
                row["Tilt"] = r.get("Tilt (default)", "")
                row["Bearing"] = bearing_val
                row["User Label"] = ""
                row["RU_effective"] = ""
                # Default context is Site ID (Step 4 may change Site ID per unit)
                row["Context_effective"] = site_id

                if ret_type == "S-RET":
                    row["ANU No"] = anu_start + idx
                    row["UID"] = ""
                    row["RSU No"] = 1
                else:
                    row["ANU No"] = anu_start
                    row["UID"] = str(r.get("UID", "")).strip()
                    row["RSU No"] = idx + 1

                out.append(row)

        return pd.DataFrame(out, columns=cols)



    # ============================================================
    # Unit keys
    # ============================================================

    def key_for_unit(row: pd.Series) -> Tuple[str, str, str, str]:
     """Uniquely identifies a logical RET unit.
     Include Facing to prevent cross-sector collisions (same AU/ANU/RSU numbers repeat per sector).
     """
     au = str(row.get("AU Ref"))
     facing = str(row.get("Facing", "")).strip()
     if str(row.get("RET TYPE", "")).strip() == "S-RET":
      return ("S", facing, au, str(row.get("ANU No")))
     return ("M", facing, au, str(row.get("RSU No")))
    def unit_label_from_key(k: Tuple[str, str, str, str]) -> str:
     t, facing, au, num = k
     return f"Facing={facing} AU={au} {'ANU' if t=='S' else 'RSU'}={num}"
    def unit_type_from_key(k: Tuple[str, str, str, str]) -> str:
     return "S-RET" if k[0] == "S" else "M-RET"
    # ============================================================
    # Label generation (lookup independent of control node)
    # ============================================================

    def build_unit_config_table(sub_df: pd.DataFrame,
                                unit_cfg: Dict[Tuple[str, str, str, str], Dict[str, Any]]) -> pd.DataFrame:
        """Build Step-4 Unit Config table (one row per logical RET unit).

        - Pairing defaults to YES only when SupportsPairing=True for the antenna model.
        - Pairing is enforced to NO for models that do not support pairing.
        """
        seen: Dict[Tuple[str, str, str], pd.Series] = {}
        for _, r in sub_df.iterrows():
            k = key_for_unit(r)
            if k not in seen:
                seen[k] = r

        rows = []
        for k, r in seen.items():
            cfg = unit_cfg.get(k, {})
            model = str(r.get("Antenna Model", "")).strip()
            pairing_default = "YES" if supports_pairing_for_model(model) else "NO"
            rows.append({
                "UnitKey": "\n".join(k),
                "Unit": unit_label_from_key(k),
                "RET Type": unit_type_from_key(k),
                "Facing": str(r.get("Facing", "")).strip(),
                "Model": model,
                "Site ID": str(cfg.get("site_id", r.get("Site ID", ""))).strip(),
                "Band": str(cfg.get("band", BAND_DISPLAY.get("N"))),
                "Tech": str(cfg.get("tech", TECH_DISPLAY.get("L"))),
                "Include 5G": bool(cfg.get("include_5g", False)),
                "Include B14 (extra)": bool(cfg.get("include_b14_extra", False)),
                "RX/TX": str(cfg.get("rx_tx", "4x4")),
     "Tilt": str(cfg.get("tilt", r.get("Tilt", ""))),
                "Pairing": str(cfg.get("pairing", pairing_default)),
                "RU override": str(cfg.get("ru_override", "")),
                "UID override": str(cfg.get("uid_override", "")),
                "Lookup LTE Node": str(cfg.get("lookup_lte", "")),
                "Lookup NR_DU Node": str(cfg.get("lookup_du", "")),
                "Lookup NR_CU Node": str(cfg.get("lookup_cu", "")),
            })

        return pd.DataFrame(rows)






    def regenerate_labels(sub_df: pd.DataFrame, usid6: str,
                          unit_cfg: Dict[Tuple[str, str, str, str], Dict[str, Any]],
                          cell_index: Dict[Tuple[str, str, str, str], List[str]]) -> Tuple[pd.DataFrame, List[str]]:
        """Generate/refresh user labels on the Subunit table.

        Option-1 tilt: when 4x4 + Pairing=YES triggers, remap tilt to match corrected Y groups:
        Y1/Y3 get tilt from (Y1 or Y2), Y2/Y4 get tilt from (Y3 or Y4), even if Step-4 tilt values were entered.
        """
        warnings: List[str] = []
        if sub_df is None or sub_df.empty:
            return sub_df, warnings

        df = sub_df.copy()
        if 'Tilt' in df.columns:
            df['Tilt'] = df['Tilt'].fillna('')

        def ant_key(row: pd.Series) -> Tuple[str, str]:
            return (str(row.get('Facing', '')).strip(), str(row.get('AU Ref', '')))

        def cfg_for_row(row: pd.Series) -> Dict[str, Any]:
            return unit_cfg.get(key_for_unit(row), {})

        # Apply overrides first
        for i, r in df.iterrows():
            cfg = cfg_for_row(r)
            site_id_eff = (cfg.get('site_id', '') or str(r.get('Site ID', ''))).strip()
            df.at[i, 'Site ID'] = site_id_eff or str(r.get('Site ID', '')).strip()
            df.at[i, 'RU_effective'] = (cfg.get('ru_override', '') or str(r.get('RU', ''))).strip()
            df.at[i, 'Context_effective'] = df.at[i, 'Site ID']
            uid_override = str(cfg.get('uid_override', '')).strip()
            if uid_override:
                df.at[i, 'UID'] = uid_override
            tilt_override = str(cfg.get('tilt', '')).strip()
            if tilt_override:
                df.at[i, 'Tilt'] = tilt_override

        # Tilt seeds after overrides
        tilt_seed: Dict[Tuple[str, str], Tuple[str, str]] = {}
        for k, g in df.groupby(df.apply(ant_key, axis=1)):
            def first_tilt_for(labels: set) -> str:
                for _, rr in g.iterrows():
                    yy = y_group(rr.get('Subunit Label', ''))
                    if yy in labels:
                        t = str(rr.get('Tilt', '')).strip()
                        if t != '':
                            return t
                return ''
            tilt_seed[k] = (first_tilt_for({'Y1','Y2'}), first_tilt_for({'Y3','Y4'}))

        def y_tilts_for_group(k_ant: Tuple[str, str]) -> Dict[str, str]:
            out: Dict[str, str] = {}
            g_all = df[df.apply(ant_key, axis=1) == k_ant]
            for yy in ['Y1','Y2','Y3','Y4']:
                cand = g_all[g_all['Subunit Label'].astype(str).str.upper().str.strip() == yy]
                if not cand.empty:
                    out[yy] = str(cand.iloc[0].get('Tilt', '')).strip()
            return out

        warned_groups: set = set()
        rx_applied_groups: set = set()
        labels_out: List[str] = [''] * len(df)

        for idx, (i, r) in enumerate(df.iterrows()):
            facing = str(r.get('Facing', '')).strip()
            position = str(r.get('AU Ref', ''))
            y = y_group(r.get('Subunit Label', ''))
            k_ant = (facing, position)
            cfg = cfg_for_row(r)

            pairing_yes = str(cfg.get('pairing', 'NO')).strip().upper() == 'YES'
            rx_norm = normalize_rxtx(str(cfg.get('rx_tx', '4x4')))

            pref_lte = cfg.get('lookup_lte', '') or str(r.get('Node_LTE', ''))
            pref_du  = cfg.get('lookup_du', '') or str(r.get('Node_NR_DU', ''))
            pref_cu  = cfg.get('lookup_cu', '') or str(r.get('Node_NR_CU', ''))
            include_5g = bool(cfg.get('include_5g', False))
            include_b14_extra = bool(cfg.get('include_b14_extra', False))

            def lte_all(band: str) -> str:
                _, cells = pick_cells(cell_index, 'LTE', band, facing, pref_lte)
                if not cells:
                    warnings.append(f"Missing LTE {band} for Facing={facing} (searched all nodes)")
                return join_cells_for_label(cells)

            def lte_one(band: str) -> str:
                _, cell = pick_one(cell_index, 'LTE', band, facing, pref_lte)
                if not cell:
                    warnings.append(f"Missing LTE {band} for Facing={facing} (searched all nodes)")
                return cell

            def nr_one(band: str, preferred: str) -> str:
                _, cell = pick_one(cell_index, 'NR', band, facing, preferred)
                if not cell:
                    warnings.append(f"Missing NR {band} for Facing={facing} (searched all nodes)")
                return cell

            band_code = decode_code(cfg.get('band', 'N')) or 'N'
            tech = decode_code(cfg.get('tech', 'L')) or 'L'

            if band_code == 'N':
                labels_out[idx] = f"{usid6}{facing}--{position}-N"
                continue

            # Default for non pairing/Y
            if y not in {'Y1','Y2','Y3','Y4'} or (not pairing_yes) or rx_norm != '4x4':
                bands = BANDCODE_TO_BANDS.get(band_code, [])
                if 'WCS' in bands:
                    tech = 'F'
                # --- RX insertion for 8x4 when combo includes PCS + (AWS and/or B66); keep B66 on AWS side ---
                if rx_norm == '8x4' and y in {'Y1','Y2','Y3','Y4'} and ('PCS' in bands) and (('AWS' in bands) or ('B66' in bands)):
                    pcs_lte_all = lte_all('PCS')
                    pcs_nr = nr_one('PCS', pref_du) if include_5g else ''
                    aws_lte_all = lte_all('AWS') if 'AWS' in bands else ''
                    b66_lte_all = lte_all('B66') if 'B66' in bands else ''
                    aws_nr = nr_one('AWS', pref_du) if include_5g else ''  # used for AWS and also for B66+PCS
                    def _dedupe_semicolon(s: str) -> str:
                        items = []
                        for t in (s or '').split(';'):
                            t = t.strip()
                            if t and t not in items:
                                items.append(t)
                        return ';'.join(items)
                    aws_side_lte = _dedupe_semicolon(';'.join([x for x in [aws_lte_all, b66_lte_all] if x]))
                    cell_part_main = cell_part_aws_pcs(
                        aws_lte_all=aws_side_lte,
                        pcs_lte_all=pcs_lte_all,
                        aws_5g=aws_nr,
                        pcs_5g=pcs_nr,
                        include_5g=include_5g,
                        rx_tx=rx_norm,
                        pairing=str(cfg.get('pairing', 'NO')),
                        y=y,
                    )
                    # Append any other bands in the same order as BANDCODE_TO_BANDS
                    extra_parts: List[str] = []
                    for b in bands:
                        if b in {'PCS','AWS','B66'}:
                            continue
                        if b in {'WCS','L700','B29','B14'}:
                            extra_parts.append(parse_cell_name_for_label(lte_one(b)))
                        elif b in {'CBAND','DOD'}:
                            extra_parts.append(parse_cell_name_for_label(nr_one(b, pref_du)))
                        elif b == '850':
                            v = nr_one('850', pref_cu) or nr_one('850', pref_du)
                            extra_parts.append(parse_cell_name_for_label(v))
                    if include_b14_extra and 'B14' not in bands:
                        extra_parts.append(parse_cell_name_for_label(lte_one('B14')))
                    cell_part = join_nonempty([cell_part_main, join_nonempty([p for p in extra_parts if p])])
                    # Message (once per antenna group)
                    if k_ant not in rx_applied_groups:
                        rx_applied_groups.add(k_ant)
                        warnings.append(f"RX applied (8x4) for Facing={facing} AU={position} Band={band_code}")
                    labels_out[idx] = build_user_label(usid6, facing, position, band_code, tech, cell_part)
                    continue
                # --- END RX insertion block ---
                parts: List[str] = []
                for b in bands:
                    if b == 'AWS':
                        parts.append(lte_all('AWS'))
                        if include_5g:
                            parts.append(parse_cell_name_for_label(nr_one('AWS', pref_du)))
                    elif b == 'PCS':
                        parts.append(lte_all('PCS'))
                        if include_5g:
                            parts.append(parse_cell_name_for_label(nr_one('PCS', pref_du)))
                    elif b in {'WCS','L700','B29','B14'}:
                        parts.append(parse_cell_name_for_label(lte_one(b)))
                    elif b == 'B66':
                        parts.append(lte_all('B66'))
                        if include_5g and 'AWS' not in bands:
                            parts.append(parse_cell_name_for_label(nr_one('AWS', pref_du)))
                    elif b in {'CBAND','DOD'}:
                        parts.append(parse_cell_name_for_label(nr_one(b, pref_du)))
                    elif b == '850':
                        v = nr_one('850', pref_cu) or nr_one('850', pref_du)
                        parts.append(parse_cell_name_for_label(v))
                if include_b14_extra and 'B14' not in bands:
                    parts.append(parse_cell_name_for_label(lte_one('B14')))
                cell_part = join_nonempty([p for p in parts if p])
                labels_out[idx] = build_user_label(usid6, facing, position, band_code, tech, cell_part)
                continue

            # Pairing correction: use antenna-level selection from Y1 if present
            g_all = df[df.apply(ant_key, axis=1) == k_ant]
            rep_cfg = cfg
            for yy in ['Y1','Y2','Y3','Y4']:
                cand = g_all[g_all['Subunit Label'].astype(str).str.upper().str.strip() == yy]
                if not cand.empty:
                    rep_cfg = cfg_for_row(cand.iloc[0])
                    break

            base_band_code = decode_code(rep_cfg.get('band', band_code)) or band_code
            base_tech = decode_code(rep_cfg.get('tech', tech)) or tech
            base_bands = BANDCODE_TO_BANDS.get(base_band_code, [])
            if 'WCS' in base_bands:
                base_tech = 'F'

            if ('AWS' in base_bands) and ('B66' in base_bands):
                other_code = 'A'
                other_bands = ['AWS','B66']
            elif 'B66' in base_bands:
                other_code = '6'
                other_bands = ['B66']
            else:
                other_code = '2'
                other_bands = ['AWS']

            group_main = {'Y1','Y3'}
            group_alt = {'Y2','Y4'}
            has_pcs = 'PCS' in base_bands
            has_other = ('AWS' in base_bands) or ('B66' in base_bands)

            if has_pcs and has_other:
                eff_code = '9' if y in group_main else other_code
                eff_bands = ['PCS'] if eff_code == '9' else other_bands
            else:
                eff_code = base_band_code if y in group_main else 'N'
                eff_bands = base_bands

            # Tilt remap even if Step-4 tilt existed
            yt = y_tilts_for_group(k_ant)
            already_aligned = (yt.get('Y1','') == yt.get('Y3','') and yt.get('Y2','') == yt.get('Y4',''))
            if not already_aligned:
                t12, t34 = tilt_seed.get(k_ant, ('',''))
                if y in group_main and t12:
                    df.at[i, 'Tilt'] = t12
                elif y in group_alt and t34:
                    df.at[i, 'Tilt'] = t34

            if eff_code == 'N':
                labels_out[idx] = f"{usid6}{facing}--{position}-N"
                continue

            # Cell part
            include_5g_rep = bool(rep_cfg.get('include_5g', False))
            if eff_code == '9':
                pcs_lte = lte_all('PCS')
                pcs_nr = parse_cell_name_for_label(nr_one('PCS', pref_du)) if include_5g_rep else ''
                cell_part = join_nonempty([pcs_lte, pcs_nr])
            else:
                aws_part = lte_all('AWS') if 'AWS' in eff_bands else ''
                b66_part = lte_all('B66') if 'B66' in eff_bands else ''
                items: List[str] = []
                for p in (aws_part.split(';') + b66_part.split(';')):
                    p = p.strip()
                    if p and p not in items:
                        items.append(p)
                if include_5g_rep and ('AWS' in eff_bands or 'B66' in eff_bands):
                    nrp = parse_cell_name_for_label(nr_one('AWS', pref_du))
                    if nrp and nrp not in items:
                        items.append(nrp)
                cell_part = ';'.join(items)

            if k_ant not in warned_groups:
                warned_groups.add(k_ant)
                warnings.append(f"AUTO-CORRECTION applied (4x4 + Pairing=YES) for Facing={facing} AU={position}: Tilt remapped.")

            labels_out[idx] = build_user_label(usid6, facing, position, eff_code, base_tech, cell_part)

        df['User Label'] = labels_out
        return df, sorted(set(warnings))

    def unit_cfg_from_table(unit_df: pd.DataFrame) -> Dict[Tuple[str, str, str, str], Dict[str, Any]]:
        """Converts the edited Step-4 table into a dict keyed by UnitKey tuple."""
        cfg = {}
        for _, r in unit_df.iterrows():
            parts = str(r.get("UnitKey", "")).split("\n")
            if len(parts) != 4:
                continue
            k = (parts[0], parts[1], parts[2], parts[3])

            cfg[k] = {
                "site_id": str(r.get("Site ID", "")).strip(),
                "band": str(r.get("Band", BAND_DISPLAY.get("N"))),
                "tech": str(r.get("Tech", TECH_DISPLAY.get("L"))),

                "include_5g": bool(r.get("Include 5G", False)),
                "include_b14_extra": bool(r.get("Include B14 (extra)", False)),
                "rx_tx": str(r.get("RX/TX", "4x4")),
     "tilt": str(r.get("Tilt", "")).strip(),
                "pairing": ("YES" if (str(r.get("Pairing", "NO")).strip().upper()=="YES" and supports_pairing_for_model(str(r.get("Model", "")).strip())) else "NO"),
                "ru_override": str(r.get("RU override", "")).strip(),
                "uid_override": str(r.get("UID override", "")).strip(),

                "lookup_lte": str(r.get("Lookup LTE Node", "")).strip(),
                "lookup_du": str(r.get("Lookup NR_DU Node", "")).strip(),
                "lookup_cu": str(r.get("Lookup NR_CU Node", "")).strip(),
            }
        return cfg

    # ============================================================
    # SCRIPT GENERATION (uses Context_effective)
    # ============================================================

    def generate_scripts(sub_df: pd.DataFrame, usid6: str) -> Tuple[str, str, str]:
        if sub_df is None or sub_df.empty:
            return "", "", ""

        # Build file_id from all unique Site IDs (edited in Step-4) separated by "_"
        site_ids = (
            sub_df.get("Site ID", pd.Series([], dtype=str))
            .fillna("")
            .astype(str)
            .str.strip()
        )
        site_ids = sorted({s for s in site_ids if s})
    
        def safe_name(s: str) -> str:
            # keep alnum, dash, underscore; replace everything else with "_"
            s = re.sub(r"[^A-Za-z0-9_-]+", "_", s)
            s = re.sub(r"_+", "_", s).strip("_")
            return s
    
        site_ids_safe = [safe_name(s) for s in site_ids if safe_name(s)]
    
        # Fallback if nothing found
        joined_sites = "_".join(site_ids_safe) if site_ids_safe else "RET_OUTPUT"
    
        # Optional: keep a reasonable length for file systems
        joined_sites = joined_sites[:180]
    
        file_id = joined_sites

        created_anus = set()
        created_rsus = set()
        created_aus = set()
        created_asus = set()
        ret_lines: List[str] = []
        cal_lines: List[str] = []

        for _, r in sub_df.iterrows():
            ctx = str(r.get("Context_effective", "")).strip() or str(r.get("Site ID", "")).strip()
            ru_eff = str(r.get("RU_effective", "")).strip() or str(r.get("RU", "")).strip()

            aug_no = str(r["AUG No"])
            aug_name = str(r["AUG Name"])
            ant_no = str(r["Ant No"])
            ret_type = str(r["RET TYPE"])

            anu_no = str(r["ANU No"])
            uid = str(r["UID"]) if pd.notna(r["UID"]) else ""
            uid_val = '<empty>' if not str(uid).strip() else f'\"{str(uid).strip()}\"'
            rsu_no = str(r["RSU No"])

            tilt = str(r["Tilt"])
            bearing = str(r["Bearing"])
            user_label = str(r["User Label"])

            au_ref = str(r["AU Ref"])
            asu_ref = str(r.get("ASU Ref", ""))
            bsid = (user_label or "").strip()[:12]

            if ret_type == "M-RET":
                device_type = "17"
                anu_key = f"{ctx}_{aug_no}_{ant_no}_{anu_no}"
            else:
                device_type = "1"
                anu_key = f"{ctx}_{aug_no}_{ant_no}_{anu_no}_{rsu_no}"

            if anu_key not in created_anus:
                created_anus.add(anu_key)
                ret_lines += [
                    "create",
                    f"FDN : SubNetwork=ONRM_ROOT_MO,MeContext={ctx},ManagedElement={ctx},Equipment=1,"
                    f"AntennaUnitGroup={aug_no},AntennaNearUnit={anu_no}",
                    "administrativeState : UNLOCKED",
                    f"antennaNearUnitId : {anu_no}",
                    "antennaUnitRef : <empty>",
                    'baseStationId : ""',
                    "configuredAisgVersion : {releaseVersion=2, majorVersion=0, minorVersion=0}",
                    'installersId : ""',
                    f"iuantDeviceType : {device_type}",
                    f"rfPortRef : \"SubNetwork=ONRM_ROOT_MO,MeContext={ctx},ManagedElement={ctx},Equipment=1,"
                    f"FieldReplaceableUnit=RRU-{ru_eff},RfPort=R\"",
                    f"uniqueId : {uid_val}",
                    "",
                ]

            # --- 2) RetSubUnit ---
            rsu_key = f"{ctx}_{aug_no}_{anu_no}_{rsu_no}"
            if rsu_key not in created_rsus:
                created_rsus.add(rsu_key)
                ret_lines += [
                    "create",
                    f"FDN : SubNetwork=ONRM_ROOT_MO,MeContext={ctx},ManagedElement={ctx},Equipment=1,"
                    f"AntennaUnitGroup={aug_no},AntennaNearUnit={anu_no},RetSubUnit={rsu_no}",
                    f"electricalAntennaTilt : {tilt}",
                    f"iuantAntennaBearing : {bearing}",
                    f"iuantBaseStationId : \"{bsid}\"",
                    f"iuantSectorId : \"{aug_name}\"",
                    f"retSubUnitId : \"{rsu_no}\"",
                    f"userLabel : \"{user_label}\"",
                    "verticalBeamWidthMode : NARROW",
                    "",
                ]

                # Calibration action (unchanged)
                cal_lines += [
                    "action",
                    f"FDN : SubNetwork=ONRM_ROOT_MO,MeContext={ctx},ManagedElement={ctx},Equipment=1,"
                    f"AntennaUnitGroup={aug_no},AntennaNearUnit={anu_no},RetSubUnit={rsu_no}",
                    "forceCalibration",
                    "",
                ]

            # --- 3) AntennaUnit ---
            au_key = f"{ctx}_{aug_no}_{au_ref}"
            if au_key not in created_aus:
                created_aus.add(au_key)
                ret_lines += [
                    "create",
                    f"FDN : SubNetwork=ONRM_ROOT_MO,MeContext={ctx},ManagedElement={ctx},Equipment=1,"
                    f"AntennaUnitGroup={aug_no},AntennaUnit={au_ref}",
                    'antennaModelNumber : ""',
                    'antennaSerialNumber : ""',
                    f"antennaUnitId : \"{au_ref}\"",
                    "mechanicalAntennaBearing : -1000",
                    "mechanicalAntennaTilt : 0",
                    'positionWithinSector : ""',
                    'sectorLabel : ""',
                    "",
                ]

            # --- 4) AntennaSubunit ---

                                                         
            asu_key = f"{ctx}_{aug_no}_{au_ref}_{asu_ref}"
            if asu_ref and asu_key not in created_asus:
                created_asus.add(asu_key)

                                                                                            
                                                                                         
             
                ret_lines += [
                    "create",
                    f"FDN : SubNetwork=ONRM_ROOT_MO,MeContext={ctx},ManagedElement={ctx},Equipment=1,"
                    f"AntennaUnitGroup={aug_no},AntennaUnit={au_ref},AntennaSubunit={asu_ref}",
                    f"antennaSubunitId : \"{asu_ref}\"",
                    f"azimuthHalfPowerBeamwidth : 65",
                    f"commonChBeamfrmPortMap : CROSS_POLARIZED",
                    f"customComChBeamfrmWtsAmplitude : [0, 0, 0, 0, 0, 0, 0, 0]",
                    f"customComChBeamfrmWtsPhase : [0, 0, 0, 0, 0, 0, 0, 0]",
                    f"maxTotalTilt : 300",
                    f"minTotalTilt : -300",
                    "",
                ]

                # --- 5) retSubunitRef set ---
                ret_subunit_fdn = (
                    f"SubNetwork=ONRM_ROOT_MO,MeContext={ctx},ManagedElement={ctx},Equipment=1,"
                    f"AntennaUnitGroup={aug_no},AntennaNearUnit={anu_no},RetSubUnit={rsu_no}"
                )
                ret_lines += [
                    "set",
                    f"FDN : SubNetwork=ONRM_ROOT_MO,MeContext={ctx},ManagedElement={ctx},Equipment=1,"
                    f"AntennaUnitGroup={aug_no},AntennaUnit={au_ref},AntennaSubunit={asu_ref}",
                    f"retSubunitRef : \"{ret_subunit_fdn}\"",
                    "",
                ]

                      
                     
                                                                                              
                                                                                      
                               
               
         

        return file_id, "\n".join(ret_lines), "\n".join(cal_lines)


    # ============================================================
    # APP STATE
    # ============================================================

    def init_state():
        defaults = {
            "raw_usid": "",
            "site_id": "",
            "num_groups": 3,
            "cell_dump": "",
            "aws_band_df": None,
            "cell_df": None,
            "cell_nodes": [],
            "aws_carrier_band": {},
            "cell_index": {},
            "basic_df": None,
            "ret_df": None,
            "subunit_df": None,
            "unit_cfg_df": None,
            "unit_cfg": {},
        }
        for k, v in defaults.items():
            if k not in st.session_state:
                st.session_state[k] = v
    init_state()

    st.title("E:// RET CLI Script — v2")

    # Sidebar
    st.sidebar.header("Site-wide")
    raw_usid = st.sidebar.text_input("USID (6 digits; auto 0-pad)", key="raw_usid")
    usid6 = pad_usid(raw_usid)
    st.sidebar.caption(f"USID (padded): {usid6 or '—'}")

    step = st.sidebar.radio(
        "Workflow",
        [
            "Step 0: Paste Cell Dump",
            "Step 1: Basic Input",
            "Step 2: Database",
            "Step 3: RET Input",
            "Step 4: Unit Config (table) + Labels",
            "Step 5: Generate Scripts",
        ]
    , key="workflow_step"
    )

    if step == "Step 0: Paste Cell Dump":
        st.header("Step 0 — Paste cell dump")
        dump_text = st.text_area("Cells", key="cell_dump", height=320)

        c1, c2 = st.columns([1, 1])
        with c1:
            parse_clicked = st.button("Parse")
        with c2:
            build_clicked = st.button("Build index")

        if parse_clicked:
            df = parse_dump(dump_text)
            st.session_state["cell_df"] = df
            nodes = sorted([n for n in df["node"].dropna().astype(str).unique().tolist() if n.strip()])
            st.session_state["cell_nodes"] = nodes

            aws_lte = df[(df["rat"] == "LTE") & (df["band"] == "AWS") & (df["node"].astype(str).str.len() > 0)]
            if not aws_lte.empty:
                cand = (
                    aws_lte[["node", "facing", "carrier"]]
                    .drop_duplicates()
                    .sort_values(["node", "facing", "carrier"])
                    .rename(columns={"node": "Node", "facing": "Facing", "carrier": "Carrier"})
                    .reset_index(drop=True)
                )
                cand["Band"] = "AWS"
                st.session_state["aws_band_df"] = cand
            else:
                st.session_state["aws_band_df"] = None

            st.success("Parsed")

        if st.session_state.get("cell_df") is not None:
            st.subheader("Parsed cells")
            st.dataframe(st.session_state["cell_df"], use_container_width=True)

        if st.session_state.get("aws_band_df") is not None:
            st.subheader("AWS carrier band confirmation (AWS vs BWE)")
            st.caption('Select "BWE" when the LTE carrier should be treated as Band 66 (B66) for labeling.')

            with st.form("aws_band_form", clear_on_submit=False):
                edited_aws = st.data_editor(
                    st.session_state["aws_band_df"],
                    use_container_width=True,
                    key="aws_band_editor",
                    column_config={
                        "Band": st.column_config.SelectboxColumn("Band", options=["AWS", "BWE"])
                    },
                    disabled=["Node", "Facing", "Carrier"],
                )
                save_aws = st.form_submit_button("Save AWS/BWE Mapping")

            if save_aws:
                st.session_state["aws_band_df"] = edited_aws
                st.success("AWS/BWE mapping saved.")

        if build_clicked:
            df = st.session_state.get("cell_df")
            if df is None or df.empty:
                st.warning("Parse the cell dump first")
            else:
                aws_map = {}
                aws_tbl = st.session_state.get("aws_band_df")
                if aws_tbl is not None and not aws_tbl.empty:
                    for _, rr in aws_tbl.iterrows():
                        val = str(rr["Band"]).strip().upper() or "AWS"
                        if val == "BWE":
                            val = "B66"
                        aws_map[(str(rr["Node"]), str(rr["Facing"]).upper(), str(rr["Carrier"]))] = val
                st.session_state["aws_carrier_band"] = aws_map
                st.session_state["cell_index"] = build_cell_index(df, aws_map)
                st.success("Index built")

    elif step == "Step 1: Basic Input":
        st.header("Step 1 — Basic Input")

        st.text_input("Site ID", value=(usid6 or ""), key="site_id")
        st.number_input("Number of AUGs", min_value=1, max_value=12,
                        value=st.session_state.get("num_groups", 3), key="num_groups")

        groups = []
        for i in range(int(st.session_state.get("num_groups", 3))):
            c1, c2, c3 = st.columns([2, 1, 1])
            aug_name = c1.selectbox(f"AUG Name #{i+1}", list(AUG_MAP.keys()), key=f"aug_{i}")
            ant_count = c2.number_input(f"Antennas in {aug_name}", min_value=1, max_value=48, value=3, key=f"ant_{i}")
            azimuth = c3.number_input(f"Azimuth for {aug_name}", min_value=0, max_value=359, value=0, key=f"az_{i}")
            groups.append({"aug_name": aug_name, "ant_count": int(ant_count), "azimuth": azimuth})

        if st.button("Create", key="create_basic"):
            site_id = str(st.session_state.get("site_id", "")).strip()
            st.session_state["basic_df"] = build_basic_input(site_id, groups)
            st.session_state["ret_df"] = None
            st.session_state["subunit_df"] = None
            st.session_state["unit_cfg_df"] = None
            st.session_state["unit_cfg"] = {}
            st.success("Created")

        if st.session_state.get("basic_df") is not None:
            st.dataframe(st.session_state["basic_df"], use_container_width=True)

    elif step == "Step 2: Database":
        st.header("Step 2 — Model Database")
        st.dataframe(DB_DF, use_container_width=True)

    elif step == "Step 3: RET Input":
        st.header("Step 3 — RET Input")
        if st.session_state.get("basic_df") is None:
            st.warning("Complete Step 1 first")
        else:
            models = sorted(DB_DF["AntennaModel"].astype(str).unique().tolist())
            if st.session_state.get("ret_df") is None:
                st.session_state["ret_df"] = create_ret_input(st.session_state["basic_df"])

            st.info("Edits are saved when you click **Save RET Input** (prevents losing text mid-typing).")
            with st.form("ret_input_form", clear_on_submit=False):
                edited_ret = st.data_editor(
                    st.session_state["ret_df"],
                    use_container_width=True,
                    key="ret_editor",
                    column_config={
                        "Antenna Model": st.column_config.SelectboxColumn("Antenna Model", options=models),
                        "RET TYPE": st.column_config.SelectboxColumn("RET TYPE", options=RET_TYPES),
                    },
                )
                save_ret = st.form_submit_button("Save RET Input")

            if save_ret:
                st.session_state["ret_df"] = edited_ret
                st.success("RET Input saved.")

    elif step == "Step 4: Unit Config (table) + Labels":
        st.header("Step 4 — Unit Config (table-wise)")

        if st.session_state.get("ret_df") is None:
            st.warning("Complete Step 3 first")
        elif not st.session_state.get("cell_index"):
            st.warning("Paste/parse cell dump in Step 0 first")
        elif not usid6:
            st.warning("Enter USID in sidebar")
        else:
            if st.button("Generate Subunit Input"):
                st.session_state["subunit_df"] = generate_subunit_input(st.session_state["ret_df"], DB_DF)
                st.session_state["unit_cfg_df"] = None
                st.success("Subunit Input generated")

            sub_df = st.session_state.get("subunit_df")
            if sub_df is not None and not sub_df.empty:
                if st.session_state.get("unit_cfg_df") is None:
                    st.session_state["unit_cfg_df"] = build_unit_config_table(sub_df, st.session_state.get("unit_cfg") or {})

                nodes = st.session_state.get("cell_nodes", [])
                node_opts = [""] + nodes

                with st.form("unit_cfg_form", clear_on_submit=False):
                    edited = st.data_editor(
                        st.session_state["unit_cfg_df"],
                        use_container_width=True,
                        key="unit_editor",
                        column_config={
                            "Site ID": st.column_config.TextColumn("Site ID"),
                            "Band": st.column_config.SelectboxColumn("Band", options=BAND_DISPLAY_OPTIONS),
                            "Tech": st.column_config.SelectboxColumn("Tech", options=TECH_DISPLAY_OPTIONS),
                            "Include 5G": st.column_config.CheckboxColumn("Include 5G"),
                            "Include B14 (extra)": st.column_config.CheckboxColumn("Include B14 (extra)"),
                            "RX/TX": st.column_config.SelectboxColumn("RX/TX", options=["4x4", "8x4"]),
                            "Tilt": st.column_config.NumberColumn("Tilt", step=1, min_value=-300, max_value=300),
                            "Pairing": st.column_config.SelectboxColumn("Pairing", options=["YES", "NO"]),
                            "Lookup LTE Node": st.column_config.SelectboxColumn("Lookup LTE Node", options=node_opts),
                            "Lookup NR_DU Node": st.column_config.SelectboxColumn("Lookup NR_DU Node", options=node_opts),
                            "Lookup NR_CU Node": st.column_config.SelectboxColumn("Lookup NR_CU Node", options=node_opts),
                        },
                        disabled=["UnitKey", "Unit", "RET Type", "Facing", "Model"],
                    )
                    apply_cfg = st.form_submit_button("Apply Unit Config Changes")

                if apply_cfg:
                    st.session_state["unit_cfg_df"] = edited
                    st.session_state["unit_cfg"] = unit_cfg_from_table(edited)
                    st.success("Unit config saved.")

                if st.button("Generate User Labels"):
                    updated, warns = regenerate_labels(
                        sub_df,
                        usid6,
                        st.session_state.get("unit_cfg") or {},
                        st.session_state.get("cell_index") or {},
                    )
                    st.session_state["subunit_df"] = updated
                    if warns:
                        st.info("Messages / warnings:")
                        st.write(warns)
                    st.success("User Labels generated")

                st.subheader("Subunit Input (with User Labels)")
                st.dataframe(st.session_state.get("subunit_df"), use_container_width=True)

    else:
        st.header("Step 5 — Generate scripts")
        df = st.session_state.get("subunit_df")
        if df is None or df.empty:
            st.warning("Generate labels in Step 4 first")
        elif not usid6:
            st.warning("Enter USID in sidebar")
        else:
            updated, warns = regenerate_labels(
                df,
                usid6,
                st.session_state.get("unit_cfg") or {},
                st.session_state.get("cell_index") or {},
            )
            st.session_state["subunit_df"] = updated
            if warns:
                st.info("Messages / warnings:")
                st.write(warns)

            file_id, ret_txt, cal_txt = generate_scripts(updated, usid6)
            st.download_button("Download RET Script", ret_txt, file_name=f"{file_id}_RET_Scripts.txt", mime="text/plain")
            st.download_button("Download Calibration", cal_txt, file_name=f"{file_id}_Calibration.txt", mime="text/plain")

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr(f"{file_id}_RET_Scripts.txt", ret_txt)
                z.writestr(f"{file_id}_Calibration.txt", cal_txt)

            st.download_button("Download ZIP", buf.getvalue(), file_name=f"{file_id}_RET_Output.zip", mime="application/zip")

# ---------------------------
# Router UI (sidebar radio)
# ---------------------------
def home_page():
    render_top_banner()
    st.title("Amentum Scripting v2")
    st.write("Select a tool from the sidebar.")

def radio_render():
    render_top_banner()
    st.header("Radio CLI")
    radio_main()

# ---- Authentication gate (must run before navigation/router) ----
require_auth_gate()

st.sidebar.write(f"Signed in as: {st.session_state.get('auth_user','')} ({st.session_state.get('auth_role','user')})")
logout_button()
st.sidebar.title("Navigation")
choices = ["Home", "RET Scripting", "Radio CLI"]
if st.session_state.get("auth_role","user") == "admin":
    choices.append("Admin")
choice = st.sidebar.radio("Choose", choices, index=0)

if choice == "Home":
    home_page()
elif choice == "RET Scripting":
    ret_render()
elif choice == "Admin":
    admin_panel()
else:
    radio_render()

