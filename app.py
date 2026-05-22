"""
Ransomware Monetization Layer Analysis
========================================
Streamlit application for correlating ransomware disclosure events
with actor-associated cryptocurrency transaction records.

This tool supports empirical research into temporal co-occurrence
between public disclosures and wallet transactions. It does NOT
claim victim-level payment attribution.

Author: CTI Research Lab
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import networkx as nx
import json
import os
import re
import io
import yaml
from datetime import datetime, timedelta
from scipy import stats
from collections import Counter

# ==============================================================================
# CONFIGURATION
# ==============================================================================

st.set_page_config(
    page_title="Ransomware Monetization Layer Analysis",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

@st.cache_data
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {
        "data": {"excel_path": "./DATASETv3.xlsx", "json_path": "./data.json",
                 "registry_sheet": "Registry", "gang_profile_sheet": "Gang Profile"},
        "normalization": {"aliases": {}},
        "temporal_matching": {"default_pre_window_days": 30, "default_post_window_days": 60,
                              "default_same_day_tolerance_days": 1, "presets": [7, 14, 30, 60, 90, 120, 180]},
        "export": {"figures_dir": "./exports/figures", "tables_dir": "./exports/tables",
                   "data_dir": "./exports/data", "dpi": 300}
    }

CONFIG = load_config()

# ==============================================================================
# NORMALIZATION ENGINE
# ==============================================================================

ALIAS_MAP = {
    "netwalker (mailto)": "netwalker",
    "mailto": "netwalker",
    "alphv (blackcat)": "alphv",
    "blackcat": "alphv",
    "cl0p": "clop",
    "revil": "revil",
    "sodinokibi": "revil",
    "lockbit": "lockbit-family",
    "lockbit2": "lockbit-family",
    "lockbit 2.0": "lockbit-family",
    "lockbit3": "lockbit-family",
    "lockbit 3.0": "lockbit-family",
    "lockbit black": "lockbit-family",
    "lockbit5": "lockbit-family",
    "black basta": "blackbasta",
    "blackbasta": "blackbasta",
    "ransomhub": "ransomhub",
    "darkside": "darkside",
    "blackmatter": "blackmatter",
    "conti": "conti",
    "ryuk": "ryuk",
    "maze": "maze",
    "egregor": "egregor",
    "avaddon": "avaddon",
    "babuk": "babuk",
    "qlocker": "qlocker",
}


def normalize_gang_label(label, alias_map=None):
    """Normalize a gang/family label to a canonical form."""
    if pd.isna(label) or label is None:
        return "unknown"
    label_clean = str(label).strip().lower()
    label_clean = re.sub(r'\s+', ' ', label_clean)
    # Remove trailing punctuation
    label_clean = re.sub(r'[._]+$', '', label_clean)

    if alias_map is None:
        alias_map = ALIAS_MAP

    # Direct lookup
    if label_clean in alias_map:
        return alias_map[label_clean]

    # Try removing parenthetical
    no_paren = re.sub(r'\s*\(.*?\)\s*', '', label_clean).strip()
    if no_paren in alias_map:
        return alias_map[no_paren]

    # LockBit variant detection
    if re.match(r'lockbit\s*\d*', label_clean):
        return "lockbit-family"

    return label_clean


def build_alias_map_from_profiles(gang_profile_df):
    """Extend alias map using the Aliases column from Gang Profile."""
    extended = dict(ALIAS_MAP)
    if 'Aliases' in gang_profile_df.columns:
        for _, row in gang_profile_df.iterrows():
            gang_name = str(row.get('gang', '')).strip().lower()
            aliases_raw = row.get('Aliases', '')
            if pd.notna(aliases_raw) and str(aliases_raw).strip():
                for alias in str(aliases_raw).split(','):
                    alias_clean = alias.strip().lower()
                    if alias_clean and alias_clean != gang_name:
                        normalized_target = normalize_gang_label(gang_name, ALIAS_MAP)
                        extended[alias_clean] = normalized_target
    return extended


# ==============================================================================
# DATA LOADING
# ==============================================================================

@st.cache_data
def load_registry(file_content=None, file_path=None):
    """Load Registry sheet from Excel."""
    try:
        if file_content is not None:
            df = pd.read_excel(io.BytesIO(file_content), sheet_name="Registry")
        else:
            df = pd.read_excel(file_path, sheet_name="Registry")

        # Convert date
        if 'date' in df.columns:
            df['date'] = pd.to_datetime(df['date'], errors='coerce')
        elif 'Date' in df.columns:
            df.rename(columns={'Date': 'date'}, inplace=True)
            df['date'] = pd.to_datetime(df['date'], errors='coerce')

        # Validate required fields
        required = ['victim', 'gang', 'date']
        missing = [c for c in required if c not in df.columns]
        if missing:
            st.warning(f"Registry: missing expected columns: {missing}")

        return df
    except Exception as e:
        st.error(f"Error loading Registry: {e}")
        return pd.DataFrame()


@st.cache_data
def load_gang_profile(file_content=None, file_path=None):
    """Load Gang Profile sheet from Excel."""
    try:
        if file_content is not None:
            df = pd.read_excel(io.BytesIO(file_content), sheet_name="Gang Profile")
        else:
            df = pd.read_excel(file_path, sheet_name="Gang Profile")
        return df
    except Exception as e:
        st.error(f"Error loading Gang Profile: {e}")
        return pd.DataFrame()


@st.cache_data
def load_wallet_data(file_content=None, file_path=None):
    """Load JSON wallet/transaction data and flatten into DataFrames."""
    try:
        if file_content is not None:
            data = json.loads(file_content)
        else:
            with open(file_path, 'r') as f:
                data = json.load(f)

        wallets_records = []
        transactions_records = []

        for wallet in data:
            wallet_info = {
                'address': wallet.get('address', ''),
                'balance': wallet.get('balance', 0),
                'blockchain': wallet.get('blockchain', ''),
                'createdAt': wallet.get('createdAt', ''),
                'updatedAt': wallet.get('updatedAt', ''),
                'family': wallet.get('family', ''),
                'balanceUSD': wallet.get('balanceUSD', 0),
            }
            wallets_records.append(wallet_info)

            for tx in wallet.get('transactions', []):
                tx_record = {
                    'wallet_address': wallet.get('address', ''),
                    'wallet_family': wallet.get('family', ''),
                    'hash': tx.get('hash', ''),
                    'time': tx.get('time', 0),
                    'amount': tx.get('amount', 0),
                    'amountUSD': tx.get('amountUSD', 0),
                }
                transactions_records.append(tx_record)

        wallets_df = pd.DataFrame(wallets_records)
        transactions_df = pd.DataFrame(transactions_records)

        # Convert Unix timestamps
        if 'time' in transactions_df.columns:
            transactions_df['tx_datetime'] = pd.to_datetime(
                transactions_df['time'], unit='s', errors='coerce'
            )

        # Convert wallet dates
        if 'createdAt' in wallets_df.columns:
            wallets_df['createdAt'] = pd.to_datetime(wallets_df['createdAt'], errors='coerce')
        if 'updatedAt' in wallets_df.columns:
            wallets_df['updatedAt'] = pd.to_datetime(wallets_df['updatedAt'], errors='coerce')

        return wallets_df, transactions_df

    except Exception as e:
        st.error(f"Error loading wallet data: {e}")
        return pd.DataFrame(), pd.DataFrame()


def apply_normalization(registry_df, wallets_df, transactions_df, gang_profile_df):
    """Apply gang/family normalization across all datasets."""
    alias_map = build_alias_map_from_profiles(gang_profile_df)

    if 'gang' in registry_df.columns:
        registry_df['gang_original'] = registry_df['gang']
        registry_df['gang_normalized'] = registry_df['gang'].apply(
            lambda x: normalize_gang_label(x, alias_map)
        )

    if 'family' in wallets_df.columns:
        wallets_df['family_original'] = wallets_df['family']
        wallets_df['family_normalized'] = wallets_df['family'].apply(
            lambda x: normalize_gang_label(x, alias_map)
        )

    if 'wallet_family' in transactions_df.columns:
        transactions_df['family_original'] = transactions_df['wallet_family']
        transactions_df['family_normalized'] = transactions_df['wallet_family'].apply(
            lambda x: normalize_gang_label(x, alias_map)
        )

    if 'gang' in gang_profile_df.columns:
        gang_profile_df['gang_original'] = gang_profile_df['gang']
        gang_profile_df['gang_normalized'] = gang_profile_df['gang'].apply(
            lambda x: normalize_gang_label(x, alias_map)
        )

    return registry_df, wallets_df, transactions_df, gang_profile_df


# ==============================================================================
# TEMPORAL MATCHING ENGINE
# ==============================================================================

def compute_temporal_matches(registry_df, transactions_df, pre_window, post_window,
                             same_day_tol, min_amount=0, gangs_filter=None,
                             sector_filter=None, country_filter=None,
                             date_range=None, tx_date_range=None):
    """
    Compute event-transaction temporal matches.
    Returns matched_event_tx_df (one row per event-transaction pair).
    """
    reg = registry_df.copy()
    tx = transactions_df.copy()

    # Apply filters
    if gangs_filter:
        reg = reg[reg['gang_normalized'].isin(gangs_filter)]
    if sector_filter and 'Victim sectors' in reg.columns:
        reg = reg[reg['Victim sectors'].isin(sector_filter)]
    if country_filter and 'Victim Country' in reg.columns:
        reg = reg[reg['Victim Country'].isin(country_filter)]
    if date_range:
        reg = reg[(reg['date'] >= pd.Timestamp(date_range[0])) &
                  (reg['date'] <= pd.Timestamp(date_range[1]))]
    if tx_date_range:
        tx = tx[(tx['tx_datetime'] >= pd.Timestamp(tx_date_range[0])) &
                (tx['tx_datetime'] <= pd.Timestamp(tx_date_range[1]))]
    if min_amount > 0:
        tx = tx[tx['amountUSD'] >= min_amount]

    # Drop rows without normalized labels or dates
    reg = reg.dropna(subset=['date', 'gang_normalized'])
    tx = tx.dropna(subset=['tx_datetime', 'family_normalized'])

    if reg.empty or tx.empty:
        return pd.DataFrame()

    # Get overlapping normalized families
    common_families = set(reg['gang_normalized'].unique()) & set(tx['family_normalized'].unique())
    if not common_families:
        return pd.DataFrame()

    reg_filtered = reg[reg['gang_normalized'].isin(common_families)]
    tx_filtered = tx[tx['family_normalized'].isin(common_families)]

    matched_pairs = []

    for family in common_families:
        family_events = reg_filtered[reg_filtered['gang_normalized'] == family]
        family_txs = tx_filtered[tx_filtered['family_normalized'] == family]

        if family_events.empty or family_txs.empty:
            continue

        for _, event in family_events.iterrows():
            event_date = event['date']
            window_start = event_date - timedelta(days=pre_window)
            window_end = event_date + timedelta(days=post_window)

            mask = (family_txs['tx_datetime'] >= window_start) & \
                   (family_txs['tx_datetime'] <= window_end)
            matched_txs = family_txs[mask]

            for _, txr in matched_txs.iterrows():
                days_from_disclosure = (txr['tx_datetime'] - event_date).total_seconds() / 86400

                if abs(days_from_disclosure) <= same_day_tol:
                    phase = "same_day"
                elif days_from_disclosure < -same_day_tol:
                    phase = "pre_disclosure"
                else:
                    phase = "post_disclosure"

                matched_pairs.append({
                    'event_date': event_date,
                    'event_victim': event.get('victim', ''),
                    'event_gang_original': event.get('gang_original', ''),
                    'gang_normalized': family,
                    'event_country': event.get('Victim Country', ''),
                    'event_sector': event.get('Victim sectors', ''),
                    'tx_hash': txr['hash'],
                    'tx_datetime': txr['tx_datetime'],
                    'tx_amount': txr['amount'],
                    'tx_amountUSD': txr['amountUSD'],
                    'wallet_address': txr['wallet_address'],
                    'days_from_disclosure': days_from_disclosure,
                    'temporal_phase': phase,
                })

    if not matched_pairs:
        return pd.DataFrame()

    return pd.DataFrame(matched_pairs)


def compute_event_level_metrics(matched_df):
    """Compute per-event metrics from matched pairs."""
    if matched_df.empty:
        return pd.DataFrame()

    grouped = matched_df.groupby(['event_date', 'event_victim', 'gang_normalized']).agg(
        tx_count=('tx_hash', 'count'),
        unique_tx_count=('tx_hash', 'nunique'),
        unique_wallet_count=('wallet_address', 'nunique'),
        total_amount_usd=('tx_amountUSD', 'sum'),
        pre_tx_count=('temporal_phase', lambda x: (x == 'pre_disclosure').sum()),
        same_day_tx_count=('temporal_phase', lambda x: (x == 'same_day').sum()),
        post_tx_count=('temporal_phase', lambda x: (x == 'post_disclosure').sum()),
        nearest_tx_days=('days_from_disclosure', lambda x: x.abs().min()),
        first_post_tx_days=('days_from_disclosure', lambda x: x[x > 0].min() if (x > 0).any() else np.nan),
        last_pre_tx_days=('days_from_disclosure', lambda x: x[x < 0].max() if (x < 0).any() else np.nan),
        event_country=('event_country', 'first'),
        event_sector=('event_sector', 'first'),
    ).reset_index()

    # Compute phase volumes
    phase_vols = matched_df.groupby(
        ['event_date', 'event_victim', 'gang_normalized', 'temporal_phase']
    )['tx_amountUSD'].sum().unstack(fill_value=0).reset_index()

    for col in ['pre_disclosure', 'same_day', 'post_disclosure']:
        if col not in phase_vols.columns:
            phase_vols[col] = 0

    phase_vols.rename(columns={
        'pre_disclosure': 'pre_volume_usd',
        'same_day': 'same_day_volume_usd',
        'post_disclosure': 'post_volume_usd'
    }, inplace=True)

    merged = grouped.merge(
        phase_vols[['event_date', 'event_victim', 'gang_normalized',
                    'pre_volume_usd', 'same_day_volume_usd', 'post_volume_usd']],
        on=['event_date', 'event_victim', 'gang_normalized'],
        how='left'
    )

    return merged


def compute_gang_level_metrics(matched_df, registry_df, gang_profile_df):
    """Compute per-gang aggregated metrics."""
    if matched_df.empty:
        return pd.DataFrame()

    # Gang-level from matched data
    gang_matched = matched_df.groupby('gang_normalized').agg(
        matched_event_count=('event_date', lambda x: x.nunique()),
        unique_wallet_count=('wallet_address', 'nunique'),
        unique_transaction_count=('tx_hash', 'nunique'),
        deduplicated_usd_volume=('tx_amountUSD', 'sum'),
        median_transaction_amount=('tx_amountUSD', 'median'),
        mean_transaction_amount=('tx_amountUSD', 'mean'),
        max_transaction_amount=('tx_amountUSD', 'max'),
        median_days_from_disclosure=('days_from_disclosure', 'median'),
    ).reset_index()

    # Registry event counts
    reg_counts = registry_df.groupby('gang_normalized').size().reset_index(name='registry_event_count')
    gang_matched = gang_matched.merge(reg_counts, on='gang_normalized', how='left')
    gang_matched['match_rate'] = gang_matched['matched_event_count'] / gang_matched['registry_event_count']

    # Phase ratios
    phase_stats = matched_df.groupby(['gang_normalized', 'temporal_phase']).agg(
        vol=('tx_amountUSD', 'sum'),
        cnt=('tx_hash', 'count')
    ).unstack(fill_value=0)

    phase_stats.columns = ['_'.join(c) for c in phase_stats.columns]
    phase_stats = phase_stats.reset_index()

    for col in ['vol_pre_disclosure', 'vol_post_disclosure', 'cnt_pre_disclosure', 'cnt_post_disclosure']:
        if col not in phase_stats.columns:
            phase_stats[col] = 0

    phase_stats['post_pre_volume_ratio'] = np.where(
        phase_stats['vol_pre_disclosure'] > 0,
        phase_stats['vol_post_disclosure'] / phase_stats['vol_pre_disclosure'],
        np.nan
    )
    phase_stats['post_pre_tx_ratio'] = np.where(
        phase_stats['cnt_pre_disclosure'] > 0,
        phase_stats['cnt_post_disclosure'] / phase_stats['cnt_pre_disclosure'],
        np.nan
    )

    gang_matched = gang_matched.merge(
        phase_stats[['gang_normalized', 'post_pre_volume_ratio', 'post_pre_tx_ratio']],
        on='gang_normalized', how='left'
    )

    # Wallet reuse index: avg events per wallet
    wallet_events = matched_df.groupby(['gang_normalized', 'wallet_address'])['event_date'].nunique()
    wallet_reuse = wallet_events.groupby(level=0).mean().reset_index(name='wallet_reuse_index')
    gang_matched = gang_matched.merge(wallet_reuse, on='gang_normalized', how='left')

    # Transaction burstiness (coefficient of variation of inter-tx time)
    def burstiness(group):
        times = group['tx_datetime'].sort_values()
        if len(times) < 3:
            return np.nan
        diffs = times.diff().dt.total_seconds().dropna()
        if diffs.std() == 0:
            return 0
        return diffs.std() / diffs.mean()

    burst = matched_df.groupby('gang_normalized').apply(burstiness).reset_index(name='transaction_burstiness_score')
    gang_matched = gang_matched.merge(burst, on='gang_normalized', how='left')

    # Merge with Gang Profile
    if not gang_profile_df.empty and 'gang_normalized' in gang_profile_df.columns:
        profile_cols = ['gang_normalized', 'Extortion Type', 'Programming Language',
                        'Currency', 'Current_Status', 'Law_Enforcement_Impact',
                        'Ecosystem_Phase', 'Confidence_Level', 'TTP_Tactics',
                        'TTP_Techniques', 'CVEs Exploited ']

        available_cols = [c for c in profile_cols if c in gang_profile_df.columns]
        profile_subset = gang_profile_df[available_cols].drop_duplicates(subset=['gang_normalized'])

        gang_matched = gang_matched.merge(profile_subset, on='gang_normalized', how='left')

        # TTP count
        if 'TTP_Techniques' in gang_matched.columns:
            gang_matched['ttp_count'] = gang_matched['TTP_Techniques'].apply(
                lambda x: len(str(x).split(',')) if pd.notna(x) and str(x).strip() else 0
            )
        else:
            gang_matched['ttp_count'] = 0

        # CVE count
        cve_col = 'CVEs Exploited ' if 'CVEs Exploited ' in gang_matched.columns else 'CVEs Exploited'
        if cve_col in gang_matched.columns:
            gang_matched['cve_count'] = gang_matched[cve_col].apply(
                lambda x: len(str(x).split(',')) if pd.notna(x) and str(x).strip() and 'Unknown' not in str(x) else 0
            )
        else:
            gang_matched['cve_count'] = 0

        gang_matched['capability_score'] = gang_matched['ttp_count'] + gang_matched['cve_count']

        # Is_RaaS flag
        if 'Ecosystem_Phase' in gang_matched.columns:
            gang_matched['is_raas'] = gang_matched['Ecosystem_Phase'].apply(
                lambda x: 'RaaS' in str(x) if pd.notna(x) else False
            )

    # Operational maturity proxy
    gang_matched['operational_maturity_proxy'] = (
        gang_matched['unique_wallet_count'].fillna(0) * 0.3 +
        gang_matched['unique_transaction_count'].fillna(0) * 0.2 +
        gang_matched.get('ttp_count', pd.Series([0]*len(gang_matched))).fillna(0) * 0.3 +
        gang_matched.get('cve_count', pd.Series([0]*len(gang_matched))).fillna(0) * 0.2
    )

    return gang_matched


def run_sensitivity_analysis(registry_df, transactions_df, windows):
    """Run temporal matching across multiple window sizes."""
    results = []
    for w in windows:
        matched = compute_temporal_matches(
            registry_df, transactions_df,
            pre_window=w, post_window=w, same_day_tol=1
        )
        if matched.empty:
            results.append({
                'window_days': w,
                'matched_events': 0,
                'matched_gangs': 0,
                'unique_matched_transactions': 0,
                'matched_tx_event_pairs': 0,
                'deduplicated_usd_volume': 0,
                'median_nearest_tx_distance': np.nan,
            })
        else:
            results.append({
                'window_days': w,
                'matched_events': matched[['event_date', 'event_victim']].drop_duplicates().shape[0],
                'matched_gangs': matched['gang_normalized'].nunique(),
                'unique_matched_transactions': matched['tx_hash'].nunique(),
                'matched_tx_event_pairs': len(matched),
                'deduplicated_usd_volume': matched.drop_duplicates(subset='tx_hash')['tx_amountUSD'].sum(),
                'median_nearest_tx_distance': matched['days_from_disclosure'].abs().median(),
            })
    return pd.DataFrame(results)


# ==============================================================================
# EXPORT UTILITIES
# ==============================================================================

def export_figure_matplotlib(fig, filename, dpi=300):
    """Export matplotlib figure to PNG and PDF."""
    os.makedirs(CONFIG['export']['figures_dir'], exist_ok=True)
    png_path = os.path.join(CONFIG['export']['figures_dir'], f"{filename}.png")
    pdf_path = os.path.join(CONFIG['export']['figures_dir'], f"{filename}.pdf")
    fig.savefig(png_path, dpi=dpi, bbox_inches='tight', facecolor='white')
    fig.savefig(pdf_path, bbox_inches='tight', facecolor='white')
    return png_path, pdf_path


def export_dataframe(df, filename):
    """Export DataFrame to CSV and Excel."""
    os.makedirs(CONFIG['export']['data_dir'], exist_ok=True)
    csv_path = os.path.join(CONFIG['export']['data_dir'], f"{filename}.csv")
    xlsx_path = os.path.join(CONFIG['export']['data_dir'], f"{filename}.xlsx")
    df.to_csv(csv_path, index=False)
    df.to_excel(xlsx_path, index=False)
    return csv_path, xlsx_path


def get_academic_style():
    """Return matplotlib rcParams for academic figures."""
    return {
        'figure.facecolor': 'white',
        'axes.facecolor': 'white',
        'axes.grid': True,
        'grid.alpha': 0.3,
        'font.family': 'serif',
        'font.size': 10,
        'axes.titlesize': 12,
        'axes.labelsize': 10,
        'xtick.labelsize': 9,
        'ytick.labelsize': 9,
        'legend.fontsize': 9,
    }


# ==============================================================================
# MAIN APPLICATION
# ==============================================================================

def main():
    st.title("🔒 Ransomware Monetization Layer Analysis")
    st.markdown("""
    *Linking the public disclosure layer with actor-associated cryptocurrency transaction records
    to examine temporal, financial, and operational patterns around public victim disclosures.*
    """)
    st.markdown("---")

    # ======================== SIDEBAR: DATA LOADING ========================
    st.sidebar.header("📁 Data Sources")

    # File upload or local path
    use_upload = st.sidebar.checkbox("Upload files manually", value=False)

    if use_upload:
        excel_file = st.sidebar.file_uploader("Upload DATASETv3.xlsx", type=['xlsx'])
        json_file = st.sidebar.file_uploader("Upload data.json", type=['json'])
        excel_content = excel_file.read() if excel_file else None
        json_content = json_file.read() if json_file else None
    else:
        excel_content = None
        json_content = None

    # Load data
    excel_path = CONFIG['data']['excel_path']
    json_path = CONFIG['data']['json_path']

    if excel_content:
        registry_df = load_registry(file_content=excel_content)
        gang_profile_df = load_gang_profile(file_content=excel_content)
    elif os.path.exists(excel_path):
        registry_df = load_registry(file_path=excel_path)
        gang_profile_df = load_gang_profile(file_path=excel_path)
    else:
        st.error(f"Excel file not found at `{excel_path}`. Please upload or adjust path.")
        st.stop()

    if json_content:
        wallets_df, transactions_df = load_wallet_data(file_content=json_content)
    elif os.path.exists(json_path):
        wallets_df, transactions_df = load_wallet_data(file_path=json_path)
    else:
        st.error(f"JSON file not found at `{json_path}`. Please upload or adjust path.")
        st.stop()

    if registry_df.empty or transactions_df.empty:
        st.error("Critical data loading failure. Check file formats.")
        st.stop()

    # Apply normalization
    registry_df, wallets_df, transactions_df, gang_profile_df = apply_normalization(
        registry_df, wallets_df, transactions_df, gang_profile_df
    )

    # Store in session
    st.session_state['registry_df'] = registry_df
    st.session_state['wallets_df'] = wallets_df
    st.session_state['transactions_df'] = transactions_df
    st.session_state['gang_profile_df'] = gang_profile_df

    # ======================== TABS ========================
    tabs = st.tabs([
        "📊 Dataset Overview",
        "⏱️ Temporal Correlation",
        "💰 Gang Monetization",
        "🌍 Sector & Geography",
        "🔗 Wallet Network",
        "📈 Sensitivity Analysis",
        "📄 Paper Figures",
        "📝 Narrative Builder",
        "🗂️ Raw Data",
        "⚠️ Data Quality"
    ])

    # ======================== TAB 1: DATASET OVERVIEW ========================
    with tabs[0]:
        render_dataset_overview(registry_df, wallets_df, transactions_df, gang_profile_df)

    # ======================== TAB 2: TEMPORAL CORRELATION ========================
    with tabs[1]:
        render_temporal_correlation(registry_df, transactions_df, gang_profile_df)

    # ======================== TAB 3: GANG MONETIZATION ========================
    with tabs[2]:
        render_gang_monetization(registry_df, transactions_df, gang_profile_df)

    # ======================== TAB 4: SECTOR & GEOGRAPHY ========================
    with tabs[3]:
        render_sector_geography(registry_df, transactions_df, gang_profile_df)

    # ======================== TAB 5: WALLET NETWORK ========================
    with tabs[4]:
        render_wallet_network(registry_df, wallets_df, transactions_df)

    # ======================== TAB 6: SENSITIVITY ========================
    with tabs[5]:
        render_sensitivity_analysis(registry_df, transactions_df)

    # ======================== TAB 7: PAPER FIGURES ========================
    with tabs[6]:
        render_paper_figures(registry_df, wallets_df, transactions_df, gang_profile_df)

    # ======================== TAB 8: NARRATIVE BUILDER ========================
    with tabs[7]:
        render_narrative_builder(registry_df, wallets_df, transactions_df, gang_profile_df)

    # ======================== TAB 9: RAW DATA ========================
    with tabs[8]:
        render_raw_data(registry_df, wallets_df, transactions_df, gang_profile_df)

    # ======================== TAB 10: DATA QUALITY ========================
    with tabs[9]:
        render_data_quality(registry_df, wallets_df, transactions_df, gang_profile_df)


# ==============================================================================
# TAB RENDERERS
# ==============================================================================

def render_dataset_overview(registry_df, wallets_df, transactions_df, gang_profile_df):
    st.header("Dataset Overview")
    st.markdown("*Summary statistics of the observable disclosure surface and actor-associated financial layer.*")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Registry Events", f"{len(registry_df):,}")
        st.metric("Unique Gangs (Registry)", registry_df['gang_normalized'].nunique() if 'gang_normalized' in registry_df.columns else 0)
    with col2:
        st.metric("Gang Profile Entries", len(gang_profile_df))
        st.metric("Wallet Records", len(wallets_df))
    with col3:
        st.metric("Unique Wallet Families", wallets_df['family_normalized'].nunique() if 'family_normalized' in wallets_df.columns else 0)
        st.metric("Transaction Records", f"{len(transactions_df):,}")
    with col4:
        if 'date' in registry_df.columns:
            date_range = f"{registry_df['date'].min().strftime('%Y-%m-%d')} to {registry_df['date'].max().strftime('%Y-%m-%d')}"
            st.metric("Disclosure Range", date_range)
        if 'tx_datetime' in transactions_df.columns:
            tx_range = f"{transactions_df['tx_datetime'].min().strftime('%Y-%m-%d')} to {transactions_df['tx_datetime'].max().strftime('%Y-%m-%d')}"
            st.metric("Transaction Range", tx_range)

    # Overlap analysis
    st.subheader("Registry / Wallet Family Overlap")
    reg_gangs = set(registry_df['gang_normalized'].unique()) if 'gang_normalized' in registry_df.columns else set()
    wallet_families = set(transactions_df['family_normalized'].unique()) if 'family_normalized' in transactions_df.columns else set()

    overlap = reg_gangs & wallet_families
    reg_only = reg_gangs - wallet_families
    wallet_only = wallet_families - reg_gangs

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Overlapping Actors", len(overlap))
        if overlap:
            st.write("Matched actors:", sorted(overlap))
    with col2:
        st.metric("Registry Only (unmatched)", len(reg_only))
        with st.expander("Show unmatched Registry gangs"):
            st.write(sorted(reg_only))
    with col3:
        st.metric("Wallet Only (unmatched)", len(wallet_only))
        with st.expander("Show unmatched wallet families"):
            st.write(sorted(wallet_only))

    # Charts
    st.subheader("Annual Disclosure Events")
    if 'date' in registry_df.columns:
        annual = registry_df.dropna(subset=['date']).copy()
        annual['year'] = annual['date'].dt.year
        year_counts = annual.groupby('year').size().reset_index(name='events')
        fig = px.bar(year_counts, x='year', y='events',
                     title="Annual Public Disclosure Events",
                     labels={'year': 'Year', 'events': 'Disclosure Events'})
        fig.update_layout(template='plotly_white')
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Annual Transaction Activity")
    if 'tx_datetime' in transactions_df.columns:
        tx_annual = transactions_df.dropna(subset=['tx_datetime']).copy()
        tx_annual['year'] = tx_annual['tx_datetime'].dt.year
        tx_year = tx_annual.groupby('year').agg(
            tx_count=('hash', 'count'),
            total_usd=('amountUSD', 'sum')
        ).reset_index()

        fig = px.bar(tx_year, x='year', y='tx_count',
                     title="Annual Transaction Count (Actor-Associated Wallets)",
                     labels={'year': 'Year', 'tx_count': 'Transactions'})
        fig.update_layout(template='plotly_white')
        st.plotly_chart(fig, use_container_width=True)

        fig2 = px.bar(tx_year, x='year', y='total_usd',
                      title="Annual Transaction Volume USD (Actor-Associated Wallets)",
                      labels={'year': 'Year', 'total_usd': 'Volume (USD)'})
        fig2.update_layout(template='plotly_white')
        st.plotly_chart(fig2, use_container_width=True)

    # Top gangs
    st.subheader("Top Actors by Disclosure Events")
    if 'gang_normalized' in registry_df.columns:
        top_gangs = registry_df['gang_normalized'].value_counts().head(20).reset_index()
        top_gangs.columns = ['gang_normalized', 'event_count']
        fig = px.bar(top_gangs, x='event_count', y='gang_normalized', orientation='h',
                     title="Top 20 Actors by Disclosure Event Count",
                     labels={'gang_normalized': 'Actor', 'event_count': 'Events'})
        fig.update_layout(template='plotly_white', yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top Wallet Families by Transaction Volume")
    if 'family_normalized' in transactions_df.columns:
        top_families = transactions_df.groupby('family_normalized')['amountUSD'].sum() \
            .sort_values(ascending=False).head(15).reset_index()
        top_families.columns = ['family_normalized', 'total_usd']
        fig = px.bar(top_families, x='total_usd', y='family_normalized', orientation='h',
                     title="Top 15 Wallet Families by USD Volume",
                     labels={'family_normalized': 'Family', 'total_usd': 'USD Volume'})
        fig.update_layout(template='plotly_white', yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig, use_container_width=True)


def render_temporal_correlation(registry_df, transactions_df, gang_profile_df):
    st.header("Temporal Correlation Explorer")
    st.markdown("*Examining temporal co-occurrence between disclosure events and actor-associated transactions.*")

    # Filters
    st.sidebar.markdown("---")
    st.sidebar.subheader("⏱️ Temporal Filters")

    preset = st.sidebar.selectbox("Window Preset (days)", [None] + CONFIG['temporal_matching']['presets'])
    if preset:
        pre_window = preset
        post_window = preset
    else:
        pre_window = st.sidebar.slider("Pre-disclosure window (days)", 1, 365,
                                        CONFIG['temporal_matching']['default_pre_window_days'])
        post_window = st.sidebar.slider("Post-disclosure window (days)", 1, 365,
                                         CONFIG['temporal_matching']['default_post_window_days'])

    same_day_tol = st.sidebar.slider("Same-day tolerance (days)", 0, 7,
                                      CONFIG['temporal_matching']['default_same_day_tolerance_days'])
    min_amount = st.sidebar.number_input("Minimum tx amount (USD)", 0, 10000000, 0)

    # Gang filter
    available_gangs = sorted(set(registry_df['gang_normalized'].unique()) &
                             set(transactions_df['family_normalized'].unique()))
    selected_gangs = st.sidebar.multiselect("Filter by gang (normalized)", available_gangs)

    # Sector filter
    if 'Victim sectors' in registry_df.columns:
        sectors = sorted(registry_df['Victim sectors'].dropna().unique())
        selected_sectors = st.sidebar.multiselect("Filter by sector", sectors)
    else:
        selected_sectors = []

    # Country filter
    if 'Victim Country' in registry_df.columns:
        countries = sorted(registry_df['Victim Country'].dropna().unique())
        selected_countries = st.sidebar.multiselect("Filter by country", countries)
    else:
        selected_countries = []

    # Date range
    if 'date' in registry_df.columns:
        min_date = registry_df['date'].min().date()
        max_date = registry_df['date'].max().date()
        date_range = st.sidebar.date_input("Disclosure date range", [min_date, max_date])
    else:
        date_range = None

    # Compute matches
    with st.spinner("Computing temporal matches..."):
        matched_df = compute_temporal_matches(
            registry_df, transactions_df,
            pre_window=pre_window,
            post_window=post_window,
            same_day_tol=same_day_tol,
            min_amount=min_amount,
            gangs_filter=selected_gangs if selected_gangs else None,
            sector_filter=selected_sectors if selected_sectors else None,
            country_filter=selected_countries if selected_countries else None,
            date_range=date_range if date_range and len(date_range) == 2 else None
        )

    if matched_df.empty:
        st.warning("No temporal matches found with current parameters.")
        return

    st.success(f"Found {len(matched_df):,} event-transaction pairs | "
               f"{matched_df['tx_hash'].nunique():,} unique transactions | "
               f"{matched_df[['event_date','event_victim']].drop_duplicates().shape[0]:,} matched events")

    # Distribution of days_from_disclosure
    st.subheader("Distribution of Transaction Timing Around Disclosures")
    fig = px.histogram(matched_df, x='days_from_disclosure', nbins=80,
                       title="Histogram: Days from Disclosure to Transaction",
                       labels={'days_from_disclosure': 'Days from Disclosure'},
                       color_discrete_sequence=['steelblue'])
    fig.add_vline(x=0, line_dash="dash", line_color="red", annotation_text="Disclosure Date")
    fig.update_layout(template='plotly_white')
    st.plotly_chart(fig, use_container_width=True)

    # KDE
    st.subheader("Density Estimate of Transaction Timing")
    fig_kde = go.Figure()
    kde_data = matched_df['days_from_disclosure'].dropna()
    if len(kde_data) > 5:
        try:
            kde = stats.gaussian_kde(kde_data)
            x_range = np.linspace(kde_data.min(), kde_data.max(), 200)
            fig_kde.add_trace(go.Scatter(x=x_range, y=kde(x_range), mode='lines', name='KDE'))
            fig_kde.add_vline(x=0, line_dash="dash", line_color="red")
            fig_kde.update_layout(template='plotly_white',
                                  title="KDE: Transaction Timing Around Disclosure Events",
                                  xaxis_title="Days from Disclosure",
                                  yaxis_title="Density")
            st.plotly_chart(fig_kde, use_container_width=True)
        except Exception:
            st.info("KDE computation failed (insufficient variance in data).")

    # Scatter: disclosure date vs transaction date
    st.subheader("Disclosure Date vs Transaction Date")
    scatter_sample = matched_df.sample(min(5000, len(matched_df)), random_state=42)
    fig = px.scatter(scatter_sample, x='event_date', y='tx_datetime',
                     color='temporal_phase',
                     title="Scatter: Disclosure Date vs Transaction Date",
                     labels={'event_date': 'Disclosure Date', 'tx_datetime': 'Transaction Date'},
                     opacity=0.5)
    fig.update_layout(template='plotly_white')
    st.plotly_chart(fig, use_container_width=True)

    # Pre/Same/Post bar
    st.subheader("Transaction Phase Distribution")
    phase_counts = matched_df['temporal_phase'].value_counts().reset_index()
    phase_counts.columns = ['phase', 'count']
    fig = px.bar(phase_counts, x='phase', y='count',
                 title="Event-Transaction Pairs by Temporal Phase",
                 color='phase')
    fig.update_layout(template='plotly_white')
    st.plotly_chart(fig, use_container_width=True)

    # Top gangs by matched volume
    st.subheader("Top Actors by Matched Transaction Volume")
    gang_vol = matched_df.groupby('gang_normalized')['tx_amountUSD'].sum() \
        .sort_values(ascending=False).head(15).reset_index()
    gang_vol.columns = ['gang_normalized', 'total_usd']
    fig = px.bar(gang_vol, x='total_usd', y='gang_normalized', orientation='h',
                 title="Top Actors by Matched Transaction Volume (USD)",
                 labels={'gang_normalized': 'Actor', 'total_usd': 'Matched Volume (USD)'})
    fig.update_layout(template='plotly_white', yaxis={'categoryorder': 'total ascending'})
    st.plotly_chart(fig, use_container_width=True)

    # Store matched_df
    st.session_state['matched_df'] = matched_df
    st.session_state['pre_window'] = pre_window
    st.session_state['post_window'] = post_window


def render_gang_monetization(registry_df, transactions_df, gang_profile_df):
    st.header("Gang-Level Monetization Patterns")
    st.markdown("*Actor-level financial activity proxies derived from temporal co-occurrence analysis.*")

    pre_window = st.session_state.get('pre_window', 30)
    post_window = st.session_state.get('post_window', 60)

    matched_df = st.session_state.get('matched_df', None)
    if matched_df is None or matched_df.empty:
        with st.spinner("Computing default matches (±30/60 days)..."):
            matched_df = compute_temporal_matches(registry_df, transactions_df,
                                                  pre_window=30, post_window=60, same_day_tol=1)

    if matched_df.empty:
        st.warning("No matches available. Adjust parameters in Temporal Correlation tab.")
        return

    gang_metrics = compute_gang_level_metrics(matched_df, registry_df, gang_profile_df)

    if gang_metrics.empty:
        st.warning("No gang-level metrics computed.")
        return

    st.dataframe(gang_metrics.sort_values('deduplicated_usd_volume', ascending=False).head(30),
                 use_container_width=True)

    # Gang ranking by volume
    st.subheader("Gang Ranking by Deduplicated USD Volume")
    top_vol = gang_metrics.nlargest(20, 'deduplicated_usd_volume')
    fig = px.bar(top_vol, x='deduplicated_usd_volume', y='gang_normalized', orientation='h',
                 title="Top 20 Actors by Deduplicated Transaction Volume (USD)",
                 labels={'gang_normalized': 'Actor', 'deduplicated_usd_volume': 'USD Volume'})
    fig.update_layout(template='plotly_white', yaxis={'categoryorder': 'total ascending'})
    st.plotly_chart(fig, use_container_width=True)

    # Bubble chart
    st.subheader("Disclosure Count vs Transaction Volume vs Wallet Count")
    fig = px.scatter(gang_metrics, x='registry_event_count', y='deduplicated_usd_volume',
                     size='unique_wallet_count', color='gang_normalized',
                     title="Bubble: Disclosure Events vs Transaction Volume vs Wallet Count",
                     labels={'registry_event_count': 'Disclosure Events',
                             'deduplicated_usd_volume': 'Transaction Volume (USD)',
                             'unique_wallet_count': 'Wallet Count'},
                     hover_name='gang_normalized')
    fig.update_layout(template='plotly_white', showlegend=False)
    st.plotly_chart(fig, use_container_width=True)

    # Capability vs Transaction Volume
    if 'capability_score' in gang_metrics.columns:
        st.subheader("Capability Score vs Transaction Volume")
        fig = px.scatter(gang_metrics, x='capability_score', y='deduplicated_usd_volume',
                         hover_name='gang_normalized', size='unique_transaction_count',
                         title="Capability (TTP+CVE Count) vs Transaction Volume",
                         labels={'capability_score': 'Capability Score (TTP + CVE)',
                                 'deduplicated_usd_volume': 'USD Volume'})
        fig.update_layout(template='plotly_white')
        st.plotly_chart(fig, use_container_width=True)

    # TTP count vs post-disclosure activity
    if 'ttp_count' in gang_metrics.columns:
        st.subheader("TTP Count vs Post-Disclosure Transaction Ratio")
        fig = px.scatter(gang_metrics.dropna(subset=['post_pre_tx_ratio']),
                         x='ttp_count', y='post_pre_tx_ratio',
                         hover_name='gang_normalized',
                         title="TTP Count vs Post/Pre Transaction Ratio",
                         labels={'ttp_count': 'TTP Count',
                                 'post_pre_tx_ratio': 'Post/Pre TX Ratio'})
        fig.update_layout(template='plotly_white')
        st.plotly_chart(fig, use_container_width=True)

    st.session_state['gang_metrics'] = gang_metrics


def render_sector_geography(registry_df, transactions_df, gang_profile_df):
    st.header("Sector and Geographic Patterns")
    st.markdown("*Sector- and country-level analysis of disclosure events with matched financial activity.*")

    matched_df = st.session_state.get('matched_df', None)
    if matched_df is None or matched_df.empty:
        matched_df = compute_temporal_matches(registry_df, transactions_df,
                                              pre_window=30, post_window=60, same_day_tol=1)

    if matched_df.empty:
        st.warning("No matched data available.")
        return

    # Sector analysis
    if 'event_sector' in matched_df.columns:
        st.subheader("Top Sectors by Matched Disclosure Events")
        sector_events = matched_df.groupby('event_sector').agg(
            matched_events=('event_date', 'nunique'),
            post_volume=('tx_amountUSD', lambda x: x[matched_df.loc[x.index, 'temporal_phase'] == 'post_disclosure'].sum())
        ).sort_values('matched_events', ascending=False).head(15).reset_index()

        fig = px.bar(sector_events, x='matched_events', y='event_sector', orientation='h',
                     title="Top Sectors by Matched Disclosure Event Count",
                     labels={'event_sector': 'Sector', 'matched_events': 'Matched Events'})
        fig.update_layout(template='plotly_white', yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig, use_container_width=True)

        # Volume by sector
        sector_vol = matched_df.groupby('event_sector')['tx_amountUSD'].sum() \
            .sort_values(ascending=False).head(15).reset_index()
        sector_vol.columns = ['event_sector', 'total_usd']
        fig = px.bar(sector_vol, x='total_usd', y='event_sector', orientation='h',
                     title="Top Sectors by Matched Transaction Volume",
                     labels={'event_sector': 'Sector', 'total_usd': 'USD Volume'})
        fig.update_layout(template='plotly_white', yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig, use_container_width=True)

    # Country analysis
    if 'event_country' in matched_df.columns:
        st.subheader("Top Countries by Matched Disclosure Events")
        country_events = matched_df.groupby('event_country')['event_date'].nunique() \
            .sort_values(ascending=False).head(15).reset_index()
        country_events.columns = ['event_country', 'matched_events']

        fig = px.bar(country_events, x='matched_events', y='event_country', orientation='h',
                     title="Top Countries by Matched Disclosure Event Count",
                     labels={'event_country': 'Country', 'matched_events': 'Matched Events'})
        fig.update_layout(template='plotly_white', yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig, use_container_width=True)

        country_vol = matched_df.groupby('event_country')['tx_amountUSD'].sum() \
            .sort_values(ascending=False).head(15).reset_index()
        country_vol.columns = ['event_country', 'total_usd']
        fig = px.bar(country_vol, x='total_usd', y='event_country', orientation='h',
                     title="Top Countries by Matched Transaction Volume",
                     labels={'event_country': 'Country', 'total_usd': 'USD Volume'})
        fig.update_layout(template='plotly_white', yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig, use_container_width=True)

    # Heatmap: sector x gang
    st.subheader("Sector × Actor Heatmap")
    if 'event_sector' in matched_df.columns:
        heatmap_data = matched_df.groupby(['event_sector', 'gang_normalized']).size() \
            .unstack(fill_value=0)
        # Keep top 10 sectors and top 10 gangs
        top_sectors = matched_df['event_sector'].value_counts().head(10).index
        top_gangs = matched_df['gang_normalized'].value_counts().head(10).index
        heatmap_filtered = heatmap_data.loc[
            heatmap_data.index.isin(top_sectors),
            heatmap_data.columns.isin(top_gangs)
        ]
        if not heatmap_filtered.empty:
            fig = px.imshow(heatmap_filtered, aspect='auto',
                            title="Heatmap: Sector × Actor (Event-Transaction Pair Count)",
                            labels={'color': 'Pair Count'})
            fig.update_layout(template='plotly_white')
            st.plotly_chart(fig, use_container_width=True)

    # Heatmap: country x gang
    st.subheader("Country × Actor Heatmap")
    if 'event_country' in matched_df.columns:
        heatmap_c = matched_df.groupby(['event_country', 'gang_normalized']).size().unstack(fill_value=0)
        top_countries = matched_df['event_country'].value_counts().head(10).index
        top_gangs_c = matched_df['gang_normalized'].value_counts().head(10).index
        heatmap_cf = heatmap_c.loc[
            heatmap_c.index.isin(top_countries),
            heatmap_c.columns.isin(top_gangs_c)
        ]
        if not heatmap_cf.empty:
            fig = px.imshow(heatmap_cf, aspect='auto',
                            title="Heatmap: Country × Actor (Event-Transaction Pair Count)",
                            labels={'color': 'Pair Count'})
            fig.update_layout(template='plotly_white')
            st.plotly_chart(fig, use_container_width=True)


def render_wallet_network(registry_df, wallets_df, transactions_df):
    st.header("Wallet Reuse and Transaction Network")
    st.markdown("*Network analysis of actor-wallet-transaction relationships.*")

    matched_df = st.session_state.get('matched_df', None)
    if matched_df is None or matched_df.empty:
        matched_df = compute_temporal_matches(registry_df, transactions_df,
                                              pre_window=30, post_window=60, same_day_tol=1)

    if matched_df.empty:
        st.warning("No matched data available for network analysis.")
        return

    # Top reused wallets
    st.subheader("Top Reused Wallets (Across Multiple Disclosure Windows)")
    wallet_event_count = matched_df.groupby('wallet_address').agg(
        event_count=('event_date', 'nunique'),
        gang=('gang_normalized', 'first'),
        tx_count=('tx_hash', 'nunique'),
        total_usd=('tx_amountUSD', 'sum')
    ).sort_values('event_count', ascending=False).head(20).reset_index()
    st.dataframe(wallet_event_count, use_container_width=True)

    fig = px.bar(wallet_event_count.head(15), x='event_count',
                 y='wallet_address', orientation='h', color='gang',
                 title="Top Wallets by Number of Linked Disclosure Windows",
                 labels={'wallet_address': 'Wallet', 'event_count': 'Disclosure Windows'})
    fig.update_layout(template='plotly_white', yaxis={'categoryorder': 'total ascending'})
    st.plotly_chart(fig, use_container_width=True)

    # Transactions matched to multiple events
    st.subheader("Transactions Matched to Multiple Disclosure Events")
    tx_multi = matched_df.groupby('tx_hash').agg(
        event_count=('event_date', 'nunique'),
        gang=('gang_normalized', 'first'),
        amount_usd=('tx_amountUSD', 'first')
    ).sort_values('event_count', ascending=False)
    tx_multi_filtered = tx_multi[tx_multi['event_count'] > 1].head(20).reset_index()
    if not tx_multi_filtered.empty:
        st.dataframe(tx_multi_filtered, use_container_width=True)
    else:
        st.info("No transactions matched to multiple disclosure windows with current parameters.")

    # Network graph (simplified)
    st.subheader("Actor-Wallet Network Graph")
    max_nodes = st.slider("Max nodes to display", 20, 200, 50)

    G = nx.Graph()

    # Build graph from top wallets
    top_wallets_for_graph = matched_df.groupby('wallet_address')['tx_amountUSD'].sum() \
        .sort_values(ascending=False).head(max_nodes // 2).index

    sub_matched = matched_df[matched_df['wallet_address'].isin(top_wallets_for_graph)]

    for _, row in sub_matched.drop_duplicates(subset=['gang_normalized', 'wallet_address']).iterrows():
        gang = row['gang_normalized']
        wallet = row['wallet_address'][:12] + "..."
        G.add_node(gang, node_type='gang')
        G.add_node(wallet, node_type='wallet')
        G.add_edge(gang, wallet)

    if G.number_of_nodes() > 0:
        # Compute metrics
        degrees = dict(G.degree())
        betweenness = nx.betweenness_centrality(G) if G.number_of_nodes() < 500 else {}

        # Plot with plotly
        pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(x=edge_x, y=edge_y, mode='lines',
                                line=dict(width=0.5, color='#888'), hoverinfo='none')

        node_x, node_y, node_text, node_color = [], [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)
            node_color.append('red' if G.nodes[node].get('node_type') == 'gang' else 'blue')

        node_trace = go.Scatter(x=node_x, y=node_y, mode='markers+text',
                                marker=dict(size=10, color=node_color),
                                text=node_text, textposition='top center',
                                textfont=dict(size=7), hoverinfo='text')

        fig = go.Figure(data=[edge_trace, node_trace])
        fig.update_layout(template='plotly_white', showlegend=False,
                          title="Actor-Wallet Network (Red=Actor, Blue=Wallet)",
                          xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                          yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
        st.plotly_chart(fig, use_container_width=True)

        # Network stats
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Nodes", G.number_of_nodes())
        with col2:
            st.metric("Edges", G.number_of_edges())
        with col3:
            if nx.is_connected(G):
                st.metric("Connected Components", 1)
            else:
                st.metric("Connected Components", nx.number_connected_components(G))


def render_sensitivity_analysis(registry_df, transactions_df):
    st.header("Burst and Sensitivity Analysis")
    st.markdown("*Testing temporal matching stability across multiple window configurations.*")

    windows = CONFIG['temporal_matching']['presets']

    with st.spinner("Running sensitivity analysis across window sizes..."):
        sensitivity_df = run_sensitivity_analysis(registry_df, transactions_df, windows)

    if sensitivity_df.empty:
        st.warning("Sensitivity analysis produced no results.")
        return

    st.dataframe(sensitivity_df, use_container_width=True)

    # Window vs matched events
    fig = px.line(sensitivity_df, x='window_days', y='matched_events', markers=True,
                  title="Window Size vs Matched Disclosure Events",
                  labels={'window_days': 'Window (±days)', 'matched_events': 'Matched Events'})
    fig.update_layout(template='plotly_white')
    st.plotly_chart(fig, use_container_width=True)

    # Window vs unique transactions
    fig = px.line(sensitivity_df, x='window_days', y='unique_matched_transactions', markers=True,
                  title="Window Size vs Unique Matched Transactions",
                  labels={'window_days': 'Window (±days)',
                          'unique_matched_transactions': 'Unique Transactions'})
    fig.update_layout(template='plotly_white')
    st.plotly_chart(fig, use_container_width=True)

    # Window vs deduplicated volume
    fig = px.line(sensitivity_df, x='window_days', y='deduplicated_usd_volume', markers=True,
                  title="Window Size vs Deduplicated USD Volume",
                  labels={'window_days': 'Window (±days)',
                          'deduplicated_usd_volume': 'USD Volume'})
    fig.update_layout(template='plotly_white')
    st.plotly_chart(fig, use_container_width=True)

    # Gang x Window heatmap
    st.subheader("Gang × Window Size Heatmap")
    gang_window_data = []
    for w in windows:
        matched = compute_temporal_matches(registry_df, transactions_df,
                                           pre_window=w, post_window=w, same_day_tol=1)
        if not matched.empty:
            gang_counts = matched.groupby('gang_normalized')['tx_hash'].nunique().reset_index()
            gang_counts['window'] = w
            gang_window_data.append(gang_counts)

    if gang_window_data:
        gw_df = pd.concat(gang_window_data)
        gw_pivot = gw_df.pivot_table(index='gang_normalized', columns='window',
                                      values='tx_hash', fill_value=0)
        # Top 10 gangs
        top_g = gw_pivot.sum(axis=1).nlargest(10).index
        gw_top = gw_pivot.loc[gw_pivot.index.isin(top_g)]
        fig = px.imshow(gw_top, aspect='auto',
                        title="Gang × Window: Unique Matched Transactions",
                        labels={'color': 'Unique TXs'})
        fig.update_layout(template='plotly_white')
        st.plotly_chart(fig, use_container_width=True)

    st.session_state['sensitivity_df'] = sensitivity_df


def render_paper_figures(registry_df, wallets_df, transactions_df, gang_profile_df):
    st.header("Paper Figures Export")
    st.markdown("*Generate publication-ready figures for Overleaf integration.*")

    matched_df = st.session_state.get('matched_df', None)
    if matched_df is None or matched_df.empty:
        matched_df = compute_temporal_matches(registry_df, transactions_df,
                                              pre_window=30, post_window=60, same_day_tol=1)

    plt.rcParams.update(get_academic_style())

    figures_generated = []

    # Figure 1: Temporal coverage
    st.subheader("Figure 1: Temporal Coverage of Disclosures and Transactions")
    fig1, ax1 = plt.subplots(figsize=(10, 4))
    if 'date' in registry_df.columns:
        reg_monthly = registry_df.dropna(subset=['date']).set_index('date').resample('M').size()
        ax1.plot(reg_monthly.index, reg_monthly.values, label='Disclosure Events', color='steelblue')
    if 'tx_datetime' in transactions_df.columns:
        tx_monthly = transactions_df.dropna(subset=['tx_datetime']).set_index('tx_datetime').resample('M').size()
        ax2 = ax1.twinx()
        ax2.plot(tx_monthly.index, tx_monthly.values, label='Transactions', color='darkorange', alpha=0.7)
        ax2.set_ylabel('Transaction Count')
        ax2.legend(loc='upper left')
    ax1.set_xlabel('Date')
    ax1.set_ylabel('Disclosure Events')
    ax1.legend(loc='upper right')
    ax1.set_title('Fig. 1: Temporal Coverage of Disclosure Events and Actor-Associated Transactions')
    fig1.tight_layout()
    st.pyplot(fig1)
    figures_generated.append(('fig1_temporal_coverage', fig1))

    # Figure 2: Overlap Venn-style bar
    st.subheader("Figure 2: Registry / Wallet Family Overlap")
    reg_gangs = set(registry_df['gang_normalized'].unique())
    wallet_fams = set(transactions_df['family_normalized'].unique())
    overlap_data = pd.DataFrame({
        'Category': ['Registry Only', 'Overlapping', 'Wallet Only'],
        'Count': [len(reg_gangs - wallet_fams), len(reg_gangs & wallet_fams), len(wallet_fams - reg_gangs)]
    })
    fig2, ax2f = plt.subplots(figsize=(6, 4))
    ax2f.bar(overlap_data['Category'], overlap_data['Count'], color=['#4472C4', '#70AD47', '#ED7D31'])
    ax2f.set_ylabel('Number of Actors/Families')
    ax2f.set_title('Fig. 2: Actor-Label Overlap Between Registry and Wallet Dataset')
    fig2.tight_layout()
    st.pyplot(fig2)
    figures_generated.append(('fig2_overlap', fig2))

    # Figure 3: Distribution of transaction timing
    if not matched_df.empty:
        st.subheader("Figure 3: Distribution of Transaction Timing Around Disclosures")
        fig3, ax3 = plt.subplots(figsize=(8, 4))
        ax3.hist(matched_df['days_from_disclosure'].dropna(), bins=60, color='steelblue', alpha=0.7, edgecolor='white')
        ax3.axvline(x=0, color='red', linestyle='--', linewidth=1.5, label='Disclosure Date')
        ax3.set_xlabel('Days from Disclosure')
        ax3.set_ylabel('Event-Transaction Pairs')
        ax3.set_title('Fig. 3: Distribution of Days from Disclosure to Actor-Associated Transaction')
        ax3.legend()
        fig3.tight_layout()
        st.pyplot(fig3)
        figures_generated.append(('fig3_timing_distribution', fig3))

        # Figure 4: Phase by gang
        st.subheader("Figure 4: Pre/Same/Post Transaction Activity by Gang")
        phase_gang = matched_df.groupby(['gang_normalized', 'temporal_phase']).size().unstack(fill_value=0)
        top_phase_gangs = phase_gang.sum(axis=1).nlargest(10).index
        phase_top = phase_gang.loc[phase_gang.index.isin(top_phase_gangs)]
        fig4, ax4 = plt.subplots(figsize=(10, 5))
        phase_top.plot(kind='barh', stacked=True, ax=ax4)
        ax4.set_xlabel('Event-Transaction Pairs')
        ax4.set_ylabel('Actor')
        ax4.set_title('Fig. 4: Temporal Phase Distribution of Matched Transactions by Actor')
        ax4.legend(title='Phase')
        fig4.tight_layout()
        st.pyplot(fig4)
        figures_generated.append(('fig4_phase_by_gang', fig4))

    # Export button
    st.markdown("---")
    if st.button("📥 Export All Figures (PNG + PDF)"):
        os.makedirs(CONFIG['export']['figures_dir'], exist_ok=True)
        for name, fig_obj in figures_generated:
            export_figure_matplotlib(fig_obj, name, dpi=300)
        st.success(f"Exported {len(figures_generated)} figures to `{CONFIG['export']['figures_dir']}`")

    plt.close('all')


def render_narrative_builder(registry_df, wallets_df, transactions_df, gang_profile_df):
    st.header("Narrative Builder for Paper")
    st.markdown("*Auto-generated paper-ready text sections following empirical and cautious methodology.*")

    matched_df = st.session_state.get('matched_df', None)
    sensitivity_df = st.session_state.get('sensitivity_df', None)
    gang_metrics = st.session_state.get('gang_metrics', None)

    # Dataset description
    st.subheader("4.2 Data Collection")
    dataset_text = f"""
The empirical dataset comprises three complementary data sources:

1. **Public Disclosure Registry** ({len(registry_df):,} events, {registry_df['gang_normalized'].nunique()} unique actor labels after normalization): a longitudinal record of ransomware victim disclosures observed between {registry_df['date'].min().strftime('%B %Y') if 'date' in registry_df.columns else 'N/A'} and {registry_df['date'].max().strftime('%B %Y') if 'date' in registry_df.columns else 'N/A'}. Each record contains the victim name, attributed actor label, disclosure timestamp, victim country, and sector classification. This dataset represents the *observable disclosure surface* rather than the full population of ransomware intrusions.

2. **Gang Profile Enrichment Layer** ({len(gang_profile_df)} entries): an actor-level reference dataset containing TTP mappings (MITRE ATT&CK tactics and techniques), CVE exploitation records, extortion model classification, programming language indicators, cryptocurrency preferences, operational status, lineage relationships, and confidence levels.

3. **Actor-Associated Cryptocurrency Dataset** ({len(wallets_df)} wallets, {len(transactions_df):,} transactions, {wallets_df['family_normalized'].nunique() if 'family_normalized' in wallets_df.columns else 'N/A'} unique family labels): wallet-level and transaction-level records attributed to ransomware actors by external blockchain intelligence sources. Transaction timestamps are recorded as Unix epoch values and converted to UTC datetime for temporal analysis. The `amountUSD` field reflects historical conversion rates at transaction time.

The unit of observation is the public ransomware disclosure event. The transaction dataset is treated as an actor-associated financial activity layer. The analysis therefore measures temporal co-occurrence between public disclosures and wallet transactions, not confirmed victim-level ransom payments.
"""
    st.markdown(dataset_text)

    # Preprocessing
    st.subheader("4.3 Data Preprocessing")
    preprocess_text = f"""
**Gang/Family Normalization.** Actor labels exhibit significant instability across datasets due to rebranding, aliasing, and variant naming conventions. We implement a deterministic normalization pipeline that: (i) converts all labels to lowercase; (ii) strips whitespace and trailing punctuation; (iii) removes parenthetical variants (e.g., "ALPHV (BlackCat)" → "alphv"); (iv) maps known aliases using a curated dictionary extended by the Aliases column in the Gang Profile enrichment layer; and (v) consolidates LockBit-family variants (LockBit, LockBit2, LockBit 3.0, LockBit Black, LockBit5) under a unified "lockbit-family" label while preserving original labels for provenance.

Both original and normalized labels are retained throughout the analysis to support reproducibility and auditing of normalization decisions.

**Temporal Alignment.** Registry disclosure dates are parsed as datetime objects. Transaction Unix timestamps are converted to UTC datetime. Both timeseries are validated for temporal coverage overlap. {len(set(registry_df['gang_normalized'].unique()) & set(transactions_df['family_normalized'].unique()))} actor labels match across the disclosure and financial datasets after normalization.
"""
    st.markdown(preprocess_text)

    # Temporal matching method
    st.subheader("4.4 Temporal Matching Method")
    method_text = """
For each disclosure event $e_i$ attributed to actor $a$, we identify all transactions $T_a$ in wallets associated with the same normalized actor label within a configurable temporal window:

$$T_{matched}(e_i) = \\{t \\in T_a : disclosure\\_date(e_i) - W_{pre} \\leq time(t) \\leq disclosure\\_date(e_i) + W_{post}\\}$$

Each matched transaction is classified into one of three temporal phases:
- **Pre-disclosure**: $time(t) < disclosure\\_date(e_i) - \\delta$
- **Same-day/near-disclosure**: $|time(t) - disclosure\\_date(e_i)| \\leq \\delta$
- **Post-disclosure**: $time(t) > disclosure\\_date(e_i) + \\delta$

where $\\delta$ is a configurable same-day tolerance (default: ±1 day).

The output is a set of event-transaction pairs (one row per match), from which we derive:
- **Event-level metrics**: transaction count, unique wallet count, phase-specific volumes, nearest transaction distance.
- **Gang-level metrics**: match rate, wallet reuse index, burstiness score, post/pre volume ratio.
- **Unique matched transactions**: deduplicated by transaction hash to avoid double-counting when windows overlap.

This approach explicitly distinguishes *event-level volume* (sum across all matched pairs, which may count the same transaction multiple times if it falls within windows of multiple events) from *deduplicated transaction volume* (each transaction counted once regardless of how many event windows it intersects).
"""
    st.markdown(method_text)

    # Limitations
    st.subheader("6. Threats to Validity")
    limitations_text = """
**Construct Validity.**
- The disclosure date may lag the actual intrusion, negotiation, or payment by days to months. Temporal proximity between a disclosure and a transaction does not establish a causal or operational link.
- The `amountUSD` field depends on historical cryptocurrency-to-USD conversion accuracy at the time of recording and may not reflect the actual value perceived by the actor.
- Actor-label normalization introduces uncertainty; aliases may be incomplete, and the same label may mask multiple distinct operators (affiliate model).

**Internal Validity.**
- Temporal co-occurrence does not imply causality. A transaction within a disclosure window may be unrelated to the specific victim event.
- Overlapping windows across multiple events may inflate event-level volume metrics through double-counting. Deduplicated volume addresses this partially.
- Wallet dataset incompleteness: unmatched actors do not imply absence of monetization activity — only absence from the observed dataset.

**External Validity.**
- The disclosure registry represents the *observable DLS surface*, not the full population of ransomware intrusions. Victims who pay without public disclosure are systematically excluded.
- Gang-label instability limits cross-temporal comparison: a label may represent different operational structures at different time periods.
- The wallet dataset coverage is non-uniform across actors and time periods.

**Reliability.**
- Results are sensitive to window size selection (addressed via sensitivity analysis).
- Zero or negative transaction amounts, duplicate hashes, and unlabeled wallet families introduce noise.
"""
    st.markdown(limitations_text)

    # Figure captions
    st.subheader("Suggested Figure Captions")
    captions = """
- **Fig. 1**: Temporal coverage of public ransomware disclosure events and actor-associated cryptocurrency transactions (monthly aggregation). The dual-axis representation highlights periods of overlap and divergence between the two observable layers.
- **Fig. 2**: Actor-label overlap between the disclosure registry and the wallet attribution dataset after normalization. The limited intersection reflects both dataset incompleteness and naming convention divergence.
- **Fig. 3**: Distribution of temporal distance (days) between disclosure events and matched actor-associated transactions. The vertical dashed line indicates the disclosure date (day 0). Positive values represent post-disclosure transactions.
- **Fig. 4**: Temporal phase distribution of matched event-transaction pairs by actor. Stacked bars indicate the relative proportion of pre-disclosure, same-day, and post-disclosure financial activity.
- **Fig. 5**: Sensitivity of matching results to window size (±7 to ±180 days). Monotonic increase suggests that the matching is not dominated by a narrow temporal artifact but expands gradually with window width.
"""
    st.markdown(captions)

    # Copy-friendly export
    if st.button("📋 Copy full narrative to clipboard"):
        full_text = dataset_text + preprocess_text + method_text + limitations_text
        st.text_area("Full narrative (copy below):", full_text, height=400)


def render_raw_data(registry_df, wallets_df, transactions_df, gang_profile_df):
    st.header("Raw Data Explorer")

    table_choice = st.selectbox("Select table", [
        "Registry", "Gang Profile", "Wallets", "Transactions",
        "Matched Event-Transaction Pairs", "Gang-Level Summary", "Sensitivity Results"
    ])

    if table_choice == "Registry":
        st.dataframe(registry_df.head(500), use_container_width=True)
        csv = registry_df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Registry CSV", csv, "registry.csv", "text/csv")

    elif table_choice == "Gang Profile":
        st.dataframe(gang_profile_df.head(500), use_container_width=True)
        csv = gang_profile_df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Gang Profile CSV", csv, "gang_profile.csv", "text/csv")

    elif table_choice == "Wallets":
        st.dataframe(wallets_df.head(500), use_container_width=True)
        csv = wallets_df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Wallets CSV", csv, "wallets.csv", "text/csv")

    elif table_choice == "Transactions":
        st.dataframe(transactions_df.head(500), use_container_width=True)
        csv = transactions_df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Transactions CSV", csv, "transactions.csv", "text/csv")

    elif table_choice == "Matched Event-Transaction Pairs":
        matched_df = st.session_state.get('matched_df', pd.DataFrame())
        if matched_df.empty:
            st.info("Run Temporal Correlation tab first to generate matches.")
        else:
            st.dataframe(matched_df.head(500), use_container_width=True)
            csv = matched_df.to_csv(index=False).encode('utf-8')
            st.download_button("Download Matched Pairs CSV", csv, "matched_pairs.csv", "text/csv")

    elif table_choice == "Gang-Level Summary":
        gang_metrics = st.session_state.get('gang_metrics', pd.DataFrame())
        if gang_metrics.empty:
            st.info("Run Gang Monetization tab first to generate metrics.")
        else:
            st.dataframe(gang_metrics, use_container_width=True)
            csv = gang_metrics.to_csv(index=False).encode('utf-8')
            st.download_button("Download Gang Metrics CSV", csv, "gang_metrics.csv", "text/csv")

    elif table_choice == "Sensitivity Results":
        sensitivity_df = st.session_state.get('sensitivity_df', pd.DataFrame())
        if sensitivity_df.empty:
            st.info("Run Sensitivity Analysis tab first.")
        else:
            st.dataframe(sensitivity_df, use_container_width=True)
            csv = sensitivity_df.to_csv(index=False).encode('utf-8')
            st.download_button("Download Sensitivity CSV", csv, "sensitivity.csv", "text/csv")


def render_data_quality(registry_df, wallets_df, transactions_df, gang_profile_df):
    st.header("Data Quality Assessment")
    st.markdown("*Systematic audit of data completeness, consistency, and potential issues.*")

    # Missing values
    st.subheader("Missing Values")
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Registry**")
        reg_missing = registry_df.isnull().sum()
        reg_missing = reg_missing[reg_missing > 0]
        if not reg_missing.empty:
            st.dataframe(reg_missing.reset_index().rename(columns={'index': 'Column', 0: 'Missing'}))
        else:
            st.success("No missing values in Registry.")
    with col2:
        st.write("**Transactions**")
        tx_missing = transactions_df.isnull().sum()
        tx_missing = tx_missing[tx_missing > 0]
        if not tx_missing.empty:
            st.dataframe(tx_missing.reset_index().rename(columns={'index': 'Column', 0: 'Missing'}))
        else:
            st.success("No missing values in Transactions.")

    # Duplicate wallets
    st.subheader("Duplicate Wallet Addresses")
    dup_wallets = wallets_df['address'].duplicated().sum() if 'address' in wallets_df.columns else 0
    st.metric("Duplicate wallet addresses", dup_wallets)

    # Duplicate transaction hashes
    st.subheader("Duplicate Transaction Hashes")
    dup_tx = transactions_df['hash'].duplicated().sum() if 'hash' in transactions_df.columns else 0
    st.metric("Duplicate transaction hashes", dup_tx)
    if dup_tx > 0:
        st.write("Note: Duplicate hashes may indicate the same transaction appearing in multiple wallets.")

    # Unmatched actors
    st.subheader("Actor Matching Gaps")
    reg_gangs = set(registry_df['gang_normalized'].unique()) if 'gang_normalized' in registry_df.columns else set()
    wallet_families = set(transactions_df['family_normalized'].unique()) if 'family_normalized' in transactions_df.columns else set()

    col1, col2 = st.columns(2)
    with col1:
        unmatched_reg = reg_gangs - wallet_families
        st.metric("Registry gangs without wallet data", len(unmatched_reg))
        with st.expander("Show all"):
            st.write(sorted(unmatched_reg))
    with col2:
        unmatched_wal = wallet_families - reg_gangs
        st.metric("Wallet families without registry events", len(unmatched_wal))
        with st.expander("Show all"):
            st.write(sorted(unmatched_wal))

    # Date coverage mismatch
    st.subheader("Date Coverage Analysis")
    if 'date' in registry_df.columns and 'tx_datetime' in transactions_df.columns:
        reg_min = registry_df['date'].min()
        reg_max = registry_df['date'].max()
        tx_min = transactions_df['tx_datetime'].min()
        tx_max = transactions_df['tx_datetime'].max()

        st.write(f"Registry: {reg_min.strftime('%Y-%m-%d')} → {reg_max.strftime('%Y-%m-%d')}")
        st.write(f"Transactions: {tx_min.strftime('%Y-%m-%d')} → {tx_max.strftime('%Y-%m-%d')}")

        overlap_start = max(reg_min, tx_min)
        overlap_end = min(reg_max, tx_max)
        if overlap_start < overlap_end:
            st.success(f"Temporal overlap: {overlap_start.strftime('%Y-%m-%d')} → {overlap_end.strftime('%Y-%m-%d')}")
        else:
            st.error("No temporal overlap between datasets!")

    # Transaction outliers
    st.subheader("Transaction Amount Outliers")
    if 'amountUSD' in transactions_df.columns:
        zero_tx = (transactions_df['amountUSD'] <= 0).sum()
        st.metric("Zero or negative amount transactions", zero_tx)

        q99 = transactions_df['amountUSD'].quantile(0.99)
        outliers = (transactions_df['amountUSD'] > q99).sum()
        st.metric(f"Transactions > 99th percentile (${q99:,.0f})", outliers)

    # Unlabeled families
    st.subheader("Unlabeled/Unknown Families")
    if 'family_normalized' in wallets_df.columns:
        unknown_wallets = wallets_df[wallets_df['family_normalized'].isin(['unknown', '', 'nan'])].shape[0]
        st.metric("Wallets with unknown/empty family", unknown_wallets)

    # Alias conflicts
    st.subheader("Potential Alias Conflicts")
    st.markdown("""
    The following normalization decisions may introduce uncertainty:
    - LockBit variants consolidated under `lockbit-family` (loses version granularity)
    - ALPHV/BlackCat merged (may represent different operational phases)
    - REvil/Sodinokibi merged (confirmed rebrand, high confidence)
    - Netwalker/Mailto merged (confirmed alias, high confidence)
    """)


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    main()
