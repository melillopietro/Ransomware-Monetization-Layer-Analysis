"""
Ransomware Monetization Layer Analysis v2.0
Temporal alignment + Full narrative data export for paper generation
"""
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("Agg")
import networkx as nx
import json, os, re, io, yaml, zipfile
from datetime import datetime, timedelta
from scipy import stats

st.set_page_config(page_title="Ransomware Monetization Layer", page_icon="\U0001f512", layout="wide", initial_sidebar_state="expanded")

@st.cache_data
def load_config():
    p = os.path.join(os.path.dirname(__file__), "config.yaml")
    if os.path.exists(p):
        with open(p) as f:
            return yaml.safe_load(f)
    return {"data":{"excel_path":"./DATASETv3.xlsx","json_path":"./data.json"},"temporal_matching":{"default_pre_window_days":30,"default_post_window_days":60,"default_same_day_tolerance_days":1,"presets":[7,14,30,60,90,120,180]},"export":{"figures_dir":"./exports/figures","tables_dir":"./exports/tables","data_dir":"./exports/data","dpi":300}}

CONFIG = load_config()

ALIAS_MAP = {
    "netwalker (mailto)":"netwalker","mailto":"netwalker",
    "alphv (blackcat)":"alphv","blackcat":"alphv",
    "cl0p":"clop","revil":"revil","sodinokibi":"revil",
    "lockbit":"lockbit-family","lockbit2":"lockbit-family","lockbit 2.0":"lockbit-family",
    "lockbit3":"lockbit-family","lockbit 3.0":"lockbit-family","lockbit black":"lockbit-family","lockbit5":"lockbit-family",
    "black basta":"blackbasta","blackbasta":"blackbasta",
    "ransomhub":"ransomhub","darkside":"darkside","blackmatter":"blackmatter",
    "conti":"conti","ryuk":"ryuk","maze":"maze","egregor":"egregor",
    "avaddon":"avaddon","babuk":"babuk","qlocker":"qlocker",
}

def normalize_gang_label(label, alias_map=None):
    if pd.isna(label) or label is None: return "unknown"
    lc = re.sub(r"\s+", " ", str(label).strip().lower())
    lc = re.sub(r"[._]+$", "", lc)
    if alias_map is None: alias_map = ALIAS_MAP
    if lc in alias_map: return alias_map[lc]
    np2 = re.sub(r"\s*\(.*?\)\s*", "", lc).strip()
    if np2 in alias_map: return alias_map[np2]
    if re.match(r"lockbit\s*\d*", lc): return "lockbit-family"
    return lc

def build_alias_map(gp):
    ext = dict(ALIAS_MAP)
    if "Aliases" in gp.columns:
        for _, r in gp.iterrows():
            gn = str(r.get("gang","")).strip().lower()
            al = r.get("Aliases","")
            if pd.notna(al) and str(al).strip():
                for a in str(al).split(","):
                    ac = a.strip().lower()
                    if ac and ac != gn: ext[ac] = normalize_gang_label(gn, ALIAS_MAP)
    return ext

@st.cache_data
def load_registry(fc=None, fp=None):
    try:
        df = pd.read_excel(io.BytesIO(fc) if fc else fp, sheet_name="Registry")
        if "date" in df.columns: df["date"] = pd.to_datetime(df["date"], errors="coerce")
        elif "Date" in df.columns: df.rename(columns={"Date":"date"}, inplace=True); df["date"]=pd.to_datetime(df["date"],errors="coerce")
        return df
    except Exception as e: st.error(f"Registry load error: {e}"); return pd.DataFrame()

@st.cache_data
def load_gang_profile(fc=None, fp=None):
    try: return pd.read_excel(io.BytesIO(fc) if fc else fp, sheet_name="Gang Profile")
    except Exception as e: st.error(f"Gang Profile error: {e}"); return pd.DataFrame()

@st.cache_data
def load_wallets(fc=None, fp=None):
    try:
        data = json.loads(fc) if fc else json.load(open(fp))
        wr, tr = [], []
        for w in data:
            wr.append({"address":w.get("address",""),"balance":w.get("balance",0),"blockchain":w.get("blockchain",""),"createdAt":w.get("createdAt",""),"updatedAt":w.get("updatedAt",""),"family":w.get("family",""),"balanceUSD":w.get("balanceUSD",0)})
            for tx in w.get("transactions",[]):
                tr.append({"wallet_address":w.get("address",""),"wallet_family":w.get("family",""),"hash":tx.get("hash",""),"time":tx.get("time",0),"amount":tx.get("amount",0),"amountUSD":tx.get("amountUSD",0)})
        wdf = pd.DataFrame(wr); tdf = pd.DataFrame(tr)
        if "time" in tdf.columns: tdf["tx_datetime"] = pd.to_datetime(tdf["time"], unit="s", errors="coerce")
        return wdf, tdf
    except Exception as e: st.error(f"Wallet error: {e}"); return pd.DataFrame(), pd.DataFrame()

def apply_norm(reg, wal, tx, gp):
    am = build_alias_map(gp)
    if "gang" in reg.columns: reg["gang_original"]=reg["gang"]; reg["gang_normalized"]=reg["gang"].apply(lambda x: normalize_gang_label(x,am))
    if "family" in wal.columns: wal["family_original"]=wal["family"]; wal["family_normalized"]=wal["family"].apply(lambda x: normalize_gang_label(x,am))
    if "wallet_family" in tx.columns: tx["family_original"]=tx["wallet_family"]; tx["family_normalized"]=tx["wallet_family"].apply(lambda x: normalize_gang_label(x,am))
    if "gang" in gp.columns: gp["gang_original"]=gp["gang"]; gp["gang_normalized"]=gp["gang"].apply(lambda x: normalize_gang_label(x,am))
    return reg, wal, tx, gp

def temporal_overlap(reg, tx):
    r0,r1 = reg["date"].min(), reg["date"].max()
    t0,t1 = tx["tx_datetime"].min(), tx["tx_datetime"].max()
    return max(r0,t0), min(r1,t1), r0, r1, t0, t1

def align(reg, tx, s, e):
    return reg[(reg["date"]>=s)&(reg["date"]<=e)].copy(), tx[(tx["tx_datetime"]>=s)&(tx["tx_datetime"]<=e)].copy()

def match_temporal(reg, tx, pre_w, post_w, tol, min_amt=0, gangs=None, sectors=None, countries=None, gp=None):
    r, t = reg.copy(), tx.copy()
    if gangs: r=r[r["gang_normalized"].isin(gangs)]
    if sectors and "Victim sectors" in r.columns: r=r[r["Victim sectors"].isin(sectors)]
    if countries and "Victim Country" in r.columns: r=r[r["Victim Country"].isin(countries)]
    if min_amt>0: t=t[t["amountUSD"]>=min_amt]
    r=r.dropna(subset=["date","gang_normalized"]); t=t.dropna(subset=["tx_datetime","family_normalized"])
    if r.empty or t.empty: return pd.DataFrame()
    common = set(r["gang_normalized"].unique()) & set(t["family_normalized"].unique())
    if not common: return pd.DataFrame()
    rf=r[r["gang_normalized"].isin(common)]; tf=t[t["family_normalized"].isin(common)]
    pairs=[]
    for fam in common:
        fe=rf[rf["gang_normalized"]==fam]; ft=tf[tf["family_normalized"]==fam]
        if fe.empty or ft.empty: continue
        for _,ev in fe.iterrows():
            ed=ev["date"]; ws=ed-timedelta(days=pre_w); we=ed+timedelta(days=post_w)
            m=ft[(ft["tx_datetime"]>=ws)&(ft["tx_datetime"]<=we)]
            for _,tx_r in m.iterrows():
                d=(tx_r["tx_datetime"]-ed).total_seconds()/86400
                ph="same_day" if abs(d)<=tol else ("pre_disclosure" if d<-tol else "post_disclosure")
                pairs.append({"event_date":ed,"event_victim":ev.get("victim",""),"event_gang_original":ev.get("gang_original",""),"gang_normalized":fam,"event_country":ev.get("Victim Country",""),"event_sector":ev.get("Victim sectors",""),"tx_hash":tx_r["hash"],"tx_datetime":tx_r["tx_datetime"],"tx_amount":tx_r["amount"],"tx_amountUSD":tx_r["amountUSD"],"wallet_address":tx_r["wallet_address"],"days_from_disclosure":d,"temporal_phase":ph})
    return pd.DataFrame(pairs) if pairs else pd.DataFrame()

def compute_gang_metrics(mdf, reg, gp):
    if mdf.empty: return pd.DataFrame()
    gm=mdf.groupby("gang_normalized").agg(matched_events=("event_date",lambda x:x.nunique()),wallets=("wallet_address","nunique"),uniq_txs=("tx_hash","nunique"),ev_vol=("tx_amountUSD","sum"),median_amt=("tx_amountUSD","median"),mean_amt=("tx_amountUSD","mean"),max_amt=("tx_amountUSD","max"),median_days=("days_from_disclosure","median")).reset_index()
    dv=mdf.drop_duplicates(subset="tx_hash").groupby("gang_normalized")["tx_amountUSD"].sum().reset_index(name="dedup_vol")
    gm=gm.merge(dv,on="gang_normalized",how="left")
    rc=reg.groupby("gang_normalized").size().reset_index(name="reg_events")
    gm=gm.merge(rc,on="gang_normalized",how="left")
    gm["match_rate"]=gm["matched_events"]/gm["reg_events"]
    ps=mdf.groupby(["gang_normalized","temporal_phase"]).agg(v=("tx_amountUSD","sum"),c=("tx_hash","count")).unstack(fill_value=0)
    ps.columns=["_".join(c) for c in ps.columns]; ps=ps.reset_index()
    for col in ["v_pre_disclosure","v_post_disclosure","c_pre_disclosure","c_post_disclosure"]:
        if col not in ps.columns: ps[col]=0
    ps["post_pre_vol"]=np.where(ps["v_pre_disclosure"]>0,ps["v_post_disclosure"]/ps["v_pre_disclosure"],np.nan)
    ps["post_pre_tx"]=np.where(ps["c_pre_disclosure"]>0,ps["c_post_disclosure"]/ps["c_pre_disclosure"],np.nan)
    gm=gm.merge(ps[["gang_normalized","post_pre_vol","post_pre_tx"]],on="gang_normalized",how="left")
    we=mdf.groupby(["gang_normalized","wallet_address"])["event_date"].nunique()
    wr=we.groupby(level=0).mean().reset_index(name="wallet_reuse_idx")
    gm=gm.merge(wr,on="gang_normalized",how="left")
    def burst(g):
        t2=g["tx_datetime"].sort_values()
        if len(t2)<3: return np.nan
        df2=t2.diff().dt.total_seconds().dropna()
        return df2.std()/df2.mean() if df2.mean()>0 else 0
    b=mdf.groupby("gang_normalized").apply(burst).reset_index(name="burstiness")
    gm=gm.merge(b,on="gang_normalized",how="left")
    if not gp.empty and "gang_normalized" in gp.columns:
        pc=[c for c in ["gang_normalized","Extortion Type","Programming Language","Current_Status","Ecosystem_Phase","Confidence_Level","TTP_Techniques","CVEs Exploited ","Origin","Lineage_Parent"] if c in gp.columns]
        gm=gm.merge(gp[pc].drop_duplicates(subset=["gang_normalized"]),on="gang_normalized",how="left")
        if "TTP_Techniques" in gm.columns: gm["ttp_count"]=gm["TTP_Techniques"].apply(lambda x: len([t2 for t2 in str(x).split(",") if t2.strip().startswith("T")]) if pd.notna(x) else 0)
        else: gm["ttp_count"]=0
        cc="CVEs Exploited " if "CVEs Exploited " in gm.columns else "CVEs Exploited"
        if cc in gm.columns: gm["cve_count"]=gm[cc].apply(lambda x: len([c2 for c2 in str(x).split(",") if "CVE" in c2]) if pd.notna(x) and "CVE" in str(x) else 0)
        else: gm["cve_count"]=0
        gm["capability"]=gm["ttp_count"]+gm["cve_count"]
    return gm

def run_sensitivity(reg, tx, windows):
    res=[]
    for w in windows:
        m=match_temporal(reg,tx,w,w,1)
        if m.empty: res.append({"window":w,"events":0,"gangs":0,"uniq_tx":0,"pairs":0,"dedup_vol":0,"ev_vol":0,"median_dist":np.nan})
        else: res.append({"window":w,"events":m[["event_date","event_victim"]].drop_duplicates().shape[0],"gangs":m["gang_normalized"].nunique(),"uniq_tx":m["tx_hash"].nunique(),"pairs":len(m),"dedup_vol":m.drop_duplicates(subset="tx_hash")["tx_amountUSD"].sum(),"ev_vol":m["tx_amountUSD"].sum(),"median_dist":m["days_from_disclosure"].abs().median()})
    return pd.DataFrame(res)

def main():
    st.title("Ransomware Monetization Layer Analysis")
    st.caption("All analyses restricted to temporal intersection of disclosure and transaction datasets.")

    st.sidebar.header("Data Sources")
    up = st.sidebar.checkbox("Upload files", value=False)
    ec = jc = None
    if up:
        ef=st.sidebar.file_uploader("DATASETv3.xlsx",type=["xlsx"]); jf=st.sidebar.file_uploader("data.json",type=["json"])
        ec=ef.read() if ef else None; jc=jf.read() if jf else None

    ep=CONFIG["data"]["excel_path"]; jp=CONFIG["data"]["json_path"]
    if ec: reg=load_registry(fc=ec); gp=load_gang_profile(fc=ec)
    elif os.path.exists(ep): reg=load_registry(fp=ep); gp=load_gang_profile(fp=ep)
    else: st.error("Excel not found. Place DATASETv3.xlsx in project root or upload."); st.stop()
    if jc: wal,tx=load_wallets(fc=jc)
    elif os.path.exists(jp): wal,tx=load_wallets(fp=jp)
    else: st.error("JSON not found. Place data.json in project root or upload."); st.stop()
    if reg.empty or tx.empty: st.error("Load failure."); st.stop()

    reg,wal,tx,gp = apply_norm(reg,wal,tx,gp)
    ov_s, ov_e, r0, r1, t0, t1 = temporal_overlap(reg.dropna(subset=["date"]), tx.dropna(subset=["tx_datetime"]))
    reg_a, tx_a = align(reg.dropna(subset=["date"]), tx.dropna(subset=["tx_datetime"]), ov_s, ov_e)

    st.sidebar.markdown("---")
    st.sidebar.subheader("Temporal Alignment")
    st.sidebar.write(f"Registry: {r0.strftime('%Y-%m-%d')} to {r1.strftime('%Y-%m-%d')}")
    st.sidebar.write(f"Transactions: {t0.strftime('%Y-%m-%d')} to {t1.strftime('%Y-%m-%d')}")
    st.sidebar.success(f"**Analysis Window:** {ov_s.strftime('%Y-%m-%d')} to {ov_e.strftime('%Y-%m-%d')}")
    st.sidebar.write(f"Events (aligned): {len(reg_a):,}")
    st.sidebar.write(f"Transactions (aligned): {len(tx_a):,}")
    st.sidebar.write(f"Excluded events: {len(reg)-len(reg_a):,}")
    st.sidebar.write(f"Excluded TXs: {len(tx)-len(tx_a):,}")

    tabs = st.tabs(["Overview","Temporal Matching","Gang Monetization","Sector/Geo","Wallet Network","Sensitivity","Paper Figures","Narrative Builder","Raw Data","Data Quality"])

    with tabs[0]:
        st.header("Dataset Overview")
        st.info(f"Analysis period: **{ov_s.strftime('%Y-%m-%d')}** to **{ov_e.strftime('%Y-%m-%d')}**")
        c1,c2,c3,c4=st.columns(4)
        c1.metric("Registry (aligned)",f"{len(reg_a):,}"); c1.metric("Gangs",reg_a["gang_normalized"].nunique())
        c2.metric("Transactions (aligned)",f"{len(tx_a):,}"); c2.metric("TX Families",tx_a["family_normalized"].nunique())
        c3.metric("Wallets",len(wal)); c3.metric("Profiles",len(gp))
        rg=set(reg_a["gang_normalized"].unique()); wf=set(tx_a["family_normalized"].unique())
        c4.metric("Overlapping",len(rg&wf)); c4.metric("Reg-only",len(rg-wf))
        st.write("**Overlapping actors:**", sorted(rg&wf))
        ann=reg_a.copy(); ann["year"]=ann["date"].dt.year; yc=ann.groupby("year").size().reset_index(name="n")
        st.plotly_chart(px.bar(yc,x="year",y="n",title="Annual Disclosures (aligned)").update_layout(template="plotly_white"),use_container_width=True)
        ta=tx_a.copy(); ta["year"]=ta["tx_datetime"].dt.year; ty=ta.groupby("year").agg(n=("hash","count"),vol=("amountUSD","sum")).reset_index()
        st.plotly_chart(px.bar(ty,x="year",y="vol",title="Annual TX Volume USD (aligned)").update_layout(template="plotly_white"),use_container_width=True)
        tg=reg_a["gang_normalized"].value_counts().head(20).reset_index(); tg.columns=["gang","n"]
        st.plotly_chart(px.bar(tg,x="n",y="gang",orientation="h",title="Top 20 Gangs by Events").update_layout(template="plotly_white",yaxis={"categoryorder":"total ascending"}),use_container_width=True)

    with tabs[1]:
        st.header("Temporal Correlation Explorer")
        st.sidebar.markdown("---"); st.sidebar.subheader("Matching Config")
        preset=st.sidebar.selectbox("Preset window",options=[None]+CONFIG["temporal_matching"]["presets"],index=0)
        if preset: pw=preset; postw=preset
        else: pw=st.sidebar.slider("Pre-window (d)",1,365,30); postw=st.sidebar.slider("Post-window (d)",1,365,60)
        tol=st.sidebar.slider("Same-day tol (d)",0,7,1); mina=st.sidebar.number_input("Min USD",0,10000000,0)
        av_g=sorted(set(reg_a["gang_normalized"].unique())&set(tx_a["family_normalized"].unique()))
        sg=st.sidebar.multiselect("Gangs",av_g)
        ss=st.sidebar.multiselect("Sectors",sorted(reg_a["Victim sectors"].dropna().unique()) if "Victim sectors" in reg_a.columns else [])
        sc=st.sidebar.multiselect("Countries",sorted(reg_a["Victim Country"].dropna().unique()) if "Victim Country" in reg_a.columns else [])
        with st.spinner("Matching..."):
            mdf=match_temporal(reg_a,tx_a,pw,postw,tol,mina,sg or None,ss or None,sc or None,gp=gp)
        if mdf.empty: st.warning("No matches found."); return
        st.success(f"**{len(mdf):,}** pairs | **{mdf['tx_hash'].nunique():,}** unique TXs | **{mdf[['event_date','event_victim']].drop_duplicates().shape[0]:,}** events | **{mdf['gang_normalized'].nunique()}** actors")
        st.plotly_chart(px.histogram(mdf,x="days_from_disclosure",nbins=80,title="Days from Disclosure Distribution",color_discrete_sequence=["steelblue"]).add_vline(x=0,line_dash="dash",line_color="red").update_layout(template="plotly_white"),use_container_width=True)
        kd=mdf["days_from_disclosure"].dropna()
        if len(kd)>10:
            try:
                k=stats.gaussian_kde(kd); xr=np.linspace(kd.min(),kd.max(),200)
                fk=go.Figure(); fk.add_trace(go.Scatter(x=xr,y=k(xr),mode="lines")); fk.add_vline(x=0,line_dash="dash",line_color="red")
                fk.update_layout(template="plotly_white",title="KDE: Transaction Timing",xaxis_title="Days",yaxis_title="Density")
                st.plotly_chart(fk,use_container_width=True)
            except: pass
        pc2=mdf["temporal_phase"].value_counts().reset_index(); pc2.columns=["phase","count"]
        pv2=mdf.groupby("temporal_phase")["tx_amountUSD"].sum().reset_index(); pv2.columns=["phase","vol"]
        c1,c2=st.columns(2)
        c1.plotly_chart(px.bar(pc2,x="phase",y="count",color="phase",title="Pairs by Phase").update_layout(template="plotly_white"),use_container_width=True)
        c2.plotly_chart(px.bar(pv2,x="phase",y="vol",color="phase",title="Volume by Phase (USD)").update_layout(template="plotly_white"),use_container_width=True)
        gv=mdf.groupby("gang_normalized")["tx_amountUSD"].sum().nlargest(15).reset_index(); gv.columns=["gang","usd"]
        st.plotly_chart(px.bar(gv,x="usd",y="gang",orientation="h",title="Top Actors by Matched Volume").update_layout(template="plotly_white",yaxis={"categoryorder":"total ascending"}),use_container_width=True)
        st.session_state["mdf"]=mdf

    with tabs[2]:
        st.header("Gang-Level Monetization")
        mdf2=st.session_state.get("mdf")
        if mdf2 is None or mdf2.empty: mdf2=match_temporal(reg_a,tx_a,30,60,1)
        if mdf2.empty: st.warning("No data."); return
        gm=compute_gang_metrics(mdf2,reg_a,gp)
        if gm.empty: st.warning("No metrics."); return
        st.dataframe(gm.sort_values("dedup_vol",ascending=False).head(25),use_container_width=True)
        st.plotly_chart(px.bar(gm.nlargest(15,"dedup_vol"),x="dedup_vol",y="gang_normalized",orientation="h",title="Top by Dedup Volume").update_layout(template="plotly_white",yaxis={"categoryorder":"total ascending"}),use_container_width=True)
        st.plotly_chart(px.scatter(gm,x="reg_events",y="dedup_vol",size="wallets",color="gang_normalized",hover_name="gang_normalized",title="Events vs Volume vs Wallets").update_layout(template="plotly_white",showlegend=False),use_container_width=True)
        if "capability" in gm.columns:
            st.plotly_chart(px.scatter(gm,x="capability",y="dedup_vol",hover_name="gang_normalized",title="Capability vs Volume").update_layout(template="plotly_white"),use_container_width=True)
        st.session_state["gm"]=gm

    with tabs[3]:
        st.header("Sector and Geography")
        mdf3=st.session_state.get("mdf")
        if mdf3 is None or mdf3.empty: mdf3=match_temporal(reg_a,tx_a,30,60,1)
        if mdf3.empty: st.warning("No data."); return
        if "event_sector" in mdf3.columns:
            sv=mdf3.groupby("event_sector")["tx_amountUSD"].sum().nlargest(15).reset_index(); sv.columns=["sector","usd"]
            st.plotly_chart(px.bar(sv,x="usd",y="sector",orientation="h",title="Top Sectors by Volume").update_layout(template="plotly_white",yaxis={"categoryorder":"total ascending"}),use_container_width=True)
        if "event_country" in mdf3.columns:
            cv=mdf3.groupby("event_country")["tx_amountUSD"].sum().nlargest(15).reset_index(); cv.columns=["country","usd"]
            st.plotly_chart(px.bar(cv,x="usd",y="country",orientation="h",title="Top Countries by Volume").update_layout(template="plotly_white",yaxis={"categoryorder":"total ascending"}),use_container_width=True)
        if "event_sector" in mdf3.columns:
            hm=mdf3.groupby(["event_sector","gang_normalized"]).size().unstack(fill_value=0)
            ts=mdf3["event_sector"].value_counts().head(10).index; tg2=mdf3["gang_normalized"].value_counts().head(8).index
            hf=hm.loc[hm.index.isin(ts),hm.columns.isin(tg2)]
            if not hf.empty: st.plotly_chart(px.imshow(hf,aspect="auto",title="Sector x Actor Heatmap").update_layout(template="plotly_white"),use_container_width=True)

    with tabs[4]:
        st.header("Wallet Reuse Network")
        mdf4=st.session_state.get("mdf")
        if mdf4 is None or mdf4.empty: mdf4=match_temporal(reg_a,tx_a,30,60,1)
        if mdf4.empty: st.warning("No data."); return
        we2=mdf4.groupby("wallet_address").agg(events=("event_date","nunique"),gang=("gang_normalized","first"),txs=("tx_hash","nunique"),usd=("tx_amountUSD","sum")).sort_values("events",ascending=False).head(20).reset_index()
        st.dataframe(we2,use_container_width=True)
        st.plotly_chart(px.bar(we2.head(12),x="events",y="wallet_address",orientation="h",color="gang",title="Top Wallets by Event Windows").update_layout(template="plotly_white",yaxis={"categoryorder":"total ascending"}),use_container_width=True)
        # Network
        mn=st.slider("Max nodes",20,150,50)
        tw=mdf4.groupby("wallet_address")["tx_amountUSD"].sum().nlargest(mn//2).index
        sub=mdf4[mdf4["wallet_address"].isin(tw)]
        G=nx.Graph()
        for _,row in sub.drop_duplicates(subset=["gang_normalized","wallet_address"]).iterrows():
            g2=row["gang_normalized"]; w2=row["wallet_address"][:10]+"..."
            G.add_node(g2,t="gang"); G.add_node(w2,t="wallet"); G.add_edge(g2,w2)
        if G.number_of_nodes()>0:
            pos=nx.spring_layout(G,k=2,iterations=50,seed=42)
            ex,ey=[],[]
            for e in G.edges():
                x0,y0=pos[e[0]]; x1,y1=pos[e[1]]; ex.extend([x0,x1,None]); ey.extend([y0,y1,None])
            et=go.Scatter(x=ex,y=ey,mode="lines",line=dict(width=0.5,color="#888"),hoverinfo="none")
            nx2,ny2,nt,nc=[],[],[],[]
            for n in G.nodes():
                x,y=pos[n]; nx2.append(x); ny2.append(y); nt.append(n); nc.append("red" if G.nodes[n].get("t")=="gang" else "blue")
            ntr=go.Scatter(x=nx2,y=ny2,mode="markers+text",marker=dict(size=8,color=nc),text=nt,textposition="top center",textfont=dict(size=6))
            fg=go.Figure(data=[et,ntr]); fg.update_layout(template="plotly_white",showlegend=False,title="Actor-Wallet Network",xaxis=dict(showgrid=False,zeroline=False,showticklabels=False),yaxis=dict(showgrid=False,zeroline=False,showticklabels=False))
            st.plotly_chart(fg,use_container_width=True)
            st.write(f"Nodes: {G.number_of_nodes()} | Edges: {G.number_of_edges()} | Components: {nx.number_connected_components(G)}")

    with tabs[5]:
        st.header("Sensitivity Analysis")
        with st.spinner("Computing..."): sdf=run_sensitivity(reg_a,tx_a,CONFIG["temporal_matching"]["presets"])
        if sdf.empty: st.warning("No results."); return
        st.dataframe(sdf,use_container_width=True)
        st.plotly_chart(px.line(sdf,x="window",y="events",markers=True,title="Window vs Matched Events").update_layout(template="plotly_white"),use_container_width=True)
        st.plotly_chart(px.line(sdf,x="window",y="uniq_tx",markers=True,title="Window vs Unique TXs").update_layout(template="plotly_white"),use_container_width=True)
        st.plotly_chart(px.line(sdf,x="window",y="dedup_vol",markers=True,title="Window vs Dedup Volume").update_layout(template="plotly_white"),use_container_width=True)
        st.session_state["sdf"]=sdf

    with tabs[6]:
        st.header("Paper Figures Export")
        mdf5=st.session_state.get("mdf")
        if mdf5 is None or mdf5.empty: mdf5=match_temporal(reg_a,tx_a,30,60,1)
        plt.rcParams.update({"figure.facecolor":"white","axes.facecolor":"white","axes.grid":True,"grid.alpha":0.3,"font.family":"serif","font.size":10})
        figs=[]
        f,a=plt.subplots(figsize=(10,4)); rm=reg_a.set_index("date").resample("M").size(); a.plot(rm.index,rm.values,color="steelblue",label="Disclosures"); a.set_ylabel("Events")
        a2=a.twinx(); tm=tx_a.set_index("tx_datetime").resample("M").size(); a2.plot(tm.index,tm.values,color="darkorange",alpha=.7,label="TXs"); a2.set_ylabel("TXs")
        a.legend(loc="upper left"); a2.legend(loc="upper right"); a.set_title("Temporal Coverage (Aligned)"); f.tight_layout(); st.pyplot(f); figs.append(("fig1_coverage",f))
        if not mdf5.empty:
            f2,a3=plt.subplots(figsize=(8,4)); a3.hist(mdf5["days_from_disclosure"].dropna(),bins=60,color="steelblue",alpha=.7,edgecolor="white"); a3.axvline(0,color="red",ls="--",lw=1.5); a3.set_xlabel("Days from Disclosure"); a3.set_ylabel("Pairs"); a3.set_title("Transaction Timing Distribution"); f2.tight_layout(); st.pyplot(f2); figs.append(("fig2_timing",f2))
            pg=mdf5.groupby(["gang_normalized","temporal_phase"]).size().unstack(fill_value=0)
            tp=pg.sum(axis=1).nlargest(10).index
            f3,a4=plt.subplots(figsize=(10,5)); pg.loc[pg.index.isin(tp)].plot(kind="barh",stacked=True,ax=a4); a4.set_xlabel("Pairs"); a4.set_title("Phase by Actor"); f3.tight_layout(); st.pyplot(f3); figs.append(("fig3_phase_actor",f3))
        if st.button("Export All (PNG+PDF)"):
            os.makedirs(CONFIG["export"]["figures_dir"],exist_ok=True)
            for n,fg2 in figs: fg2.savefig(os.path.join(CONFIG["export"]["figures_dir"],f"{n}.png"),dpi=300,bbox_inches="tight"); fg2.savefig(os.path.join(CONFIG["export"]["figures_dir"],f"{n}.pdf"),bbox_inches="tight")
            st.success(f"Exported {len(figs)} figures.")
        plt.close("all")

    with tabs[7]:
        st.header("Narrative Builder - Complete Paper Data Package")
        st.markdown("**Download all computed data + methodology + writing prompts as ZIP for LLM paper generation.**")
        mdf6=st.session_state.get("mdf"); sdf2=st.session_state.get("sdf"); gm3=st.session_state.get("gm")
        if mdf6 is None or mdf6.empty: mdf6=match_temporal(reg_a,tx_a,30,60,1)
        if sdf2 is None or sdf2.empty: sdf2=run_sensitivity(reg_a,tx_a,CONFIG["temporal_matching"]["presets"])
        if gm3 is None or gm3.empty: gm3=compute_gang_metrics(mdf6,reg_a,gp) if not mdf6.empty else pd.DataFrame()

        ds={"analysis_start":str(ov_s.date()),"analysis_end":str(ov_e.date()),"registry_full":len(reg),"registry_aligned":len(reg_a),"transactions_full":len(tx),"transactions_aligned":len(tx_a),"wallets":len(wal),"profiles":len(gp),"overlap_actors":sorted(list(set(reg_a["gang_normalized"].unique())&set(tx_a["family_normalized"].unique()))),"n_overlap":len(set(reg_a["gang_normalized"].unique())&set(tx_a["family_normalized"].unique())),"reg_gangs":int(reg_a["gang_normalized"].nunique()),"tx_families":int(tx_a["family_normalized"].nunique()),"total_vol_usd":float(tx_a["amountUSD"].sum()),"excluded_events":len(reg)-len(reg_a),"excluded_txs":len(tx)-len(tx_a),"reg_date_range":f"{r0.strftime('%Y-%m-%d')} to {r1.strftime('%Y-%m-%d')}","tx_date_range":f"{t0.strftime('%Y-%m-%d')} to {t1.strftime('%Y-%m-%d')}"}
        st.subheader("Dataset Statistics"); st.json(ds)

        if not mdf6.empty:
            ms={"window":"pre=30d post=60d tol=1d","pairs":len(mdf6),"uniq_tx":int(mdf6["tx_hash"].nunique()),"uniq_events":int(mdf6[["event_date","event_victim"]].drop_duplicates().shape[0]),"actors":int(mdf6["gang_normalized"].nunique()),"actor_list":sorted(mdf6["gang_normalized"].unique().tolist()),"dedup_vol":float(mdf6.drop_duplicates(subset="tx_hash")["tx_amountUSD"].sum()),"ev_vol":float(mdf6["tx_amountUSD"].sum()),"phase_pairs":mdf6["temporal_phase"].value_counts().to_dict(),"phase_vol":{k:float(v) for k,v in mdf6.groupby("temporal_phase")["tx_amountUSD"].sum().items()},"median_days":float(mdf6["days_from_disclosure"].median()),"mean_days":float(mdf6["days_from_disclosure"].mean()),"std_days":float(mdf6["days_from_disclosure"].std()),"pct_pre":round(float((mdf6["temporal_phase"]=="pre_disclosure").mean()*100),1),"pct_same":round(float((mdf6["temporal_phase"]=="same_day").mean()*100),1),"pct_post":round(float((mdf6["temporal_phase"]=="post_disclosure").mean()*100),1),"wallets_matched":int(mdf6["wallet_address"].nunique()),"percentiles":mdf6["days_from_disclosure"].describe(percentiles=[.05,.1,.25,.5,.75,.9,.95]).to_dict()}
            st.subheader("Matching Results"); st.json(ms)
            st.subheader("Auto-Narrative (RQ1)")
            st.markdown(f"""Using a 30/60-day window with 1-day tolerance within the aligned period ({ov_s.strftime('%Y-%m-%d')} to {ov_e.strftime('%Y-%m-%d')}), the engine identifies **{ms['pairs']:,}** event-transaction pairs involving **{ms['uniq_tx']:,}** unique transactions linked to **{ms['uniq_events']:,}** events across **{ms['actors']}** actors.

Phase: **{ms['pct_pre']}%** pre, **{ms['pct_same']}%** same-day, **{ms['pct_post']}%** post. Median distance: **{ms['median_days']:.1f}d** (mean: {ms['mean_days']:.1f}, std: {ms['std_days']:.1f}).

Dedup volume: **${ms['dedup_vol']:,.0f}**. Event-level: **${ms['ev_vol']:,.0f}**.""")

            # --- RQ2: Recurring Financial Signatures ---
            if gm3 is not None and not gm3.empty:
                st.subheader("Auto-Narrative (RQ2 - Financial Signatures)")
                rq2_lines = []
                if "dedup_vol" in gm3.columns:
                    top5 = gm3.nlargest(5, "dedup_vol")
                    rq2_lines.append(f"**{len(gm3)}** actors show measurable transaction co-occurrence.")
                    rq2_lines.append(f"Top 5 by deduplicated volume: {', '.join(top5['gang_normalized'].tolist())} (combined: ${top5['dedup_vol'].sum():,.0f}).")
                if "median_days" in gm3.columns:
                    fast = gm3[gm3["median_days"] <= 3]
                    slow = gm3[gm3["median_days"] > 30]
                    rq2_lines.append(f"Timing clusters: **{len(fast)}** actors with median lag <=3d (rapid pattern), **{len(slow)}** with >30d lag (delayed pattern).")
                if "wallet_reuse_idx" in gm3.columns:
                    wr_actors = gm3[gm3["wallet_reuse_idx"] > 1.5]
                    if not wr_actors.empty:
                        rq2_lines.append(f"**{len(wr_actors)}** actors show wallet reuse index >1.5, suggesting address recycling across events.")
                if "burstiness" in gm3.columns:
                    bursty = gm3[gm3["burstiness"] > gm3["burstiness"].median()]
                    rq2_lines.append(f"Burst activity: **{len(bursty)}** actors above median burstiness ({gm3['burstiness'].median():.2f}), indicating episodic monetization.")
                if rq2_lines:
                    st.markdown("\n\n".join(rq2_lines))

            # --- RQ3: Sector/Country Concentration ---
            if not mdf6.empty:
                ss_n = mdf6.groupby("event_sector").agg(ev=("event_victim", "nunique"), vol=("tx_amountUSD", "sum")).sort_values("vol", ascending=False).reset_index()
                cs_n = mdf6.groupby("event_country").agg(ev=("event_victim", "nunique"), vol=("tx_amountUSD", "sum")).sort_values("vol", ascending=False).reset_index()
                st.subheader("Auto-Narrative (RQ3 - Sector & Geographic)")
                rq3_lines = []
                if not ss_n.empty and ss_n["vol"].sum() > 0:
                    top_sec = ss_n.head(3)
                    top3_pct = round(top_sec["vol"].sum() / ss_n["vol"].sum() * 100, 1)
                    rq3_lines.append(f"Top 3 sectors by co-occurring volume: **{', '.join(top_sec['event_sector'].tolist())}** ({top3_pct}% of total).")
                    rq3_lines.append(f"Sector spread: **{len(ss_n)}** unique sectors with matched events.")
                if not cs_n.empty and cs_n["vol"].sum() > 0:
                    top_geo = cs_n.head(3)
                    geo_pct = round(top_geo["vol"].sum() / cs_n["vol"].sum() * 100, 1)
                    rq3_lines.append(f"Top 3 countries: **{', '.join(top_geo['event_country'].tolist())}** ({geo_pct}% of matched volume).")
                    rq3_lines.append(f"Geographic spread: **{len(cs_n)}** unique countries.")
                if rq3_lines:
                    st.markdown("\n\n".join(rq3_lines))

            # --- RQ4: Operational Maturity ---
            if gm3 is not None and not gm3.empty and "matched_events" in gm3.columns:
                st.subheader("Auto-Narrative (RQ4 - Operational Maturity)")
                rq4_lines = []
                high_vol = gm3.nlargest(5, "matched_events")
                rq4_lines.append(f"Most active actors by matched events: **{', '.join(high_vol['gang_normalized'].tolist())}**.")
                if "dedup_vol" in gm3.columns:
                    gm3_tmp = gm3.copy()
                    gm3_tmp["vol_per_event"] = gm3_tmp["dedup_vol"] / gm3_tmp["matched_events"].replace(0, np.nan)
                    efficient = gm3_tmp.nlargest(5, "vol_per_event").dropna(subset=["vol_per_event"])
                    if not efficient.empty:
                        rq4_lines.append(f"Highest volume-per-event (monetization efficiency proxy): **{', '.join(efficient['gang_normalized'].tolist())}**.")
                if "reg_events" in gm3.columns:
                    longrun = gm3[gm3["reg_events"] > 50]
                    rq4_lines.append(f"**{len(longrun)}** actors with >50 registry events (sustained operations).")
                if "capability" in gm3.columns:
                    cap_high = gm3[gm3["capability"] > gm3["capability"].median()]
                    rq4_lines.append(f"**{len(cap_high)}** actors above median capability score (TTP+CVE count).")
                if "dedup_vol" in gm3.columns and "matched_events" in gm3.columns:
                    try:
                        from scipy import stats as sp_stats
                        r, p = sp_stats.spearmanr(gm3["matched_events"].fillna(0), gm3["dedup_vol"].fillna(0))
                        rq4_lines.append(f"Spearman correlation (matched events vs dedup volume): rho={r:.3f}, p={p:.4f}.")
                    except Exception:
                        pass
                if rq4_lines:
                    st.markdown("\n\n".join(rq4_lines))

        if st.button("GENERATE FULL DATA PACKAGE ZIP", type="primary"):
            buf=io.BytesIO()
            with zipfile.ZipFile(buf,"w",zipfile.ZIP_DEFLATED) as zf:
                # === GENERATE ALL FIGURES AS PDF (for Overleaf images/ folder) ===
                plt.style.use("seaborn-v0_8-whitegrid")
                matplotlib.rcParams.update({"font.size":10,"figure.dpi":300,"savefig.dpi":300,"pdf.fonttype":42,"ps.fonttype":42})
                fig_names = []

                # Fig1: Temporal Coverage
                try:
                    f1,a1=plt.subplots(figsize=(10,4))
                    rm2=reg_a.set_index("date").resample("M").size()
                    a1.plot(rm2.index,rm2.values,color="steelblue",label="Disclosure Events")
                    a1.set_ylabel("Events/month"); a1.set_xlabel("")
                    ax2=a1.twinx()
                    tm2=tx_a.set_index("tx_datetime").resample("M").size()
                    ax2.plot(tm2.index,tm2.values,color="darkorange",alpha=.7,label="Transactions")
                    ax2.set_ylabel("Transactions/month")
                    a1.legend(loc="upper left"); ax2.legend(loc="upper right")
                    a1.set_title("Temporal Coverage — Aligned Analysis Window")
                    f1.tight_layout()
                    buf1=io.BytesIO(); f1.savefig(buf1,format="pdf",bbox_inches="tight"); buf1.seek(0)
                    zf.writestr("images/fig1_temporal_coverage.pdf",buf1.getvalue())
                    fig_names.append(("fig1_temporal_coverage","Temporal coverage of aligned datasets"))
                    plt.close(f1)
                except Exception: pass

                # Fig2: Timing Distribution (histogram)
                if not mdf6.empty:
                    try:
                        f2,a2_=plt.subplots(figsize=(8,4))
                        a2_.hist(mdf6["days_from_disclosure"].dropna(),bins=60,color="steelblue",alpha=.8,edgecolor="white")
                        a2_.axvline(0,color="red",ls="--",lw=1.5,label="Disclosure day")
                        a2_.set_xlabel("Days from Disclosure"); a2_.set_ylabel("Event-TX Pairs")
                        a2_.set_title("Distribution of Transaction Timing Relative to Disclosure")
                        a2_.legend(); f2.tight_layout()
                        buf2=io.BytesIO(); f2.savefig(buf2,format="pdf",bbox_inches="tight"); buf2.seek(0)
                        zf.writestr("images/fig2_timing_distribution.pdf",buf2.getvalue())
                        fig_names.append(("fig2_timing_distribution","Histogram of days from disclosure to associated transactions"))
                        plt.close(f2)
                    except Exception: pass

                # Fig3: Phase by Actor (top 10)
                if not mdf6.empty:
                    try:
                        pg2=mdf6.groupby(["gang_normalized","temporal_phase"]).size().unstack(fill_value=0)
                        tp2=pg2.sum(axis=1).nlargest(10).index
                        f3,a3_=plt.subplots(figsize=(10,5))
                        pg2.loc[pg2.index.isin(tp2)].plot(kind="barh",stacked=True,ax=a3_)
                        a3_.set_xlabel("Event-TX Pairs"); a3_.set_title("Temporal Phase Distribution by Actor (Top 10)")
                        f3.tight_layout()
                        buf3=io.BytesIO(); f3.savefig(buf3,format="pdf",bbox_inches="tight"); buf3.seek(0)
                        zf.writestr("images/fig3_phase_by_actor.pdf",buf3.getvalue())
                        fig_names.append(("fig3_phase_by_actor","Stacked bar: temporal phase distribution per actor"))
                        plt.close(f3)
                    except Exception: pass

                # Fig4: Top actors by dedup volume
                if gm3 is not None and not gm3.empty and "dedup_vol" in gm3.columns:
                    try:
                        top15=gm3.nlargest(15,"dedup_vol")
                        f4,a4_=plt.subplots(figsize=(9,5))
                        a4_.barh(top15["gang_normalized"],top15["dedup_vol"],color="steelblue")
                        a4_.set_xlabel("Deduplicated Volume (USD)"); a4_.set_title("Top 15 Actors by Co-occurring Transaction Volume")
                        a4_.invert_yaxis(); f4.tight_layout()
                        buf4=io.BytesIO(); f4.savefig(buf4,format="pdf",bbox_inches="tight"); buf4.seek(0)
                        zf.writestr("images/fig4_top_actors_volume.pdf",buf4.getvalue())
                        fig_names.append(("fig4_top_actors_volume","Top 15 actors ranked by deduplicated co-occurring volume"))
                        plt.close(f4)
                    except Exception: pass

                # Fig5: Sector distribution
                if not mdf6.empty and "event_sector" in mdf6.columns:
                    try:
                        sv2=mdf6.groupby("event_sector")["tx_amountUSD"].sum().nlargest(12).reset_index()
                        sv2.columns=["sector","usd"]
                        f5,a5_=plt.subplots(figsize=(9,5))
                        a5_.barh(sv2["sector"],sv2["usd"],color="teal")
                        a5_.set_xlabel("Co-occurring Volume (USD)"); a5_.set_title("Sector Concentration of Matched Activity")
                        a5_.invert_yaxis(); f5.tight_layout()
                        buf5=io.BytesIO(); f5.savefig(buf5,format="pdf",bbox_inches="tight"); buf5.seek(0)
                        zf.writestr("images/fig5_sector_volume.pdf",buf5.getvalue())
                        fig_names.append(("fig5_sector_volume","Sector distribution of co-occurring transaction volume"))
                        plt.close(f5)
                    except Exception: pass

                # Fig6: Country distribution
                if not mdf6.empty and "event_country" in mdf6.columns:
                    try:
                        cv2=mdf6.groupby("event_country")["tx_amountUSD"].sum().nlargest(12).reset_index()
                        cv2.columns=["country","usd"]
                        f6,a6_=plt.subplots(figsize=(9,5))
                        a6_.barh(cv2["country"],cv2["usd"],color="darkslateblue")
                        a6_.set_xlabel("Co-occurring Volume (USD)"); a6_.set_title("Geographic Concentration of Matched Activity")
                        a6_.invert_yaxis(); f6.tight_layout()
                        buf6=io.BytesIO(); f6.savefig(buf6,format="pdf",bbox_inches="tight"); buf6.seek(0)
                        zf.writestr("images/fig6_country_volume.pdf",buf6.getvalue())
                        fig_names.append(("fig6_country_volume","Geographic distribution of co-occurring transaction volume"))
                        plt.close(f6)
                    except Exception: pass

                # Fig7: Sensitivity analysis
                if sdf2 is not None and not sdf2.empty:
                    try:
                        f7,a7_=plt.subplots(figsize=(8,4))
                        a7_.plot(sdf2["window"],sdf2["pairs"],marker="o",color="steelblue",label="Pairs")
                        a7_.set_xlabel("Window (days)"); a7_.set_ylabel("Pairs",color="steelblue")
                        a72=a7_.twinx()
                        a72.plot(sdf2["window"],sdf2["dedup_vol"],marker="s",color="darkorange",label="Dedup Vol")
                        a72.set_ylabel("Volume (USD)",color="darkorange")
                        a7_.set_title("Sensitivity Analysis: Window Size Impact")
                        a7_.legend(loc="upper left"); a72.legend(loc="upper right"); f7.tight_layout()
                        buf7=io.BytesIO(); f7.savefig(buf7,format="pdf",bbox_inches="tight"); buf7.seek(0)
                        zf.writestr("images/fig7_sensitivity.pdf",buf7.getvalue())
                        fig_names.append(("fig7_sensitivity","Sensitivity of matching results to window size"))
                        plt.close(f7)
                    except Exception: pass

                # Fig8: Events vs Volume scatter
                if gm3 is not None and not gm3.empty:
                    try:
                        f8,a8_=plt.subplots(figsize=(8,5))
                        sc8=a8_.scatter(gm3["matched_events"],gm3["dedup_vol"],s=gm3["wallets"]*20,alpha=.6,c="steelblue",edgecolors="white",lw=.5)
                        for _,row in gm3.nlargest(5,"dedup_vol").iterrows():
                            a8_.annotate(row["gang_normalized"],(row["matched_events"],row["dedup_vol"]),fontsize=7,alpha=.8)
                        a8_.set_xlabel("Matched Events"); a8_.set_ylabel("Deduplicated Volume (USD)")
                        a8_.set_title("Actor Activity vs Financial Volume (bubble=wallets)"); f8.tight_layout()
                        buf8=io.BytesIO(); f8.savefig(buf8,format="pdf",bbox_inches="tight"); buf8.seek(0)
                        zf.writestr("images/fig8_events_vs_volume.pdf",buf8.getvalue())
                        fig_names.append(("fig8_events_vs_volume","Scatter: matched events vs deduplicated volume, sized by wallet count"))
                        plt.close(f8)
                    except Exception: pass

                # Fig9: Wallet reuse top 15
                if not mdf6.empty:
                    try:
                        wr9=mdf6.groupby("wallet_address").agg(evts=("event_date","nunique"),gang=("gang_normalized","first")).sort_values("evts",ascending=False).head(15).reset_index()
                        wr9["label"]=wr9["wallet_address"].str[:12]+"..."
                        f9,a9_=plt.subplots(figsize=(9,5))
                        a9_.barh(wr9["label"],wr9["evts"],color="indianred")
                        a9_.set_xlabel("Distinct Event Windows"); a9_.set_title("Top 15 Wallets by Event Window Coverage")
                        a9_.invert_yaxis(); f9.tight_layout()
                        buf9=io.BytesIO(); f9.savefig(buf9,format="pdf",bbox_inches="tight"); buf9.seek(0)
                        zf.writestr("images/fig9_wallet_reuse.pdf",buf9.getvalue())
                        fig_names.append(("fig9_wallet_reuse","Top wallets by number of distinct event windows covered"))
                        plt.close(f9)
                    except Exception: pass

                # Fig10: Annual trends
                if not mdf6.empty:
                    try:
                        ann3=mdf6.copy(); ann3["year"]=ann3["event_date"].dt.year
                        ay2=ann3.groupby("year").agg(events=("event_victim","nunique"),vol=("tx_amountUSD","sum")).reset_index()
                        f10,a10=plt.subplots(figsize=(8,4))
                        a10.bar(ay2["year"],ay2["events"],color="steelblue",alpha=.7,label="Events")
                        a102=a10.twinx()
                        a102.plot(ay2["year"],ay2["vol"],color="darkorange",marker="o",label="Volume")
                        a10.set_xlabel("Year"); a10.set_ylabel("Matched Events",color="steelblue")
                        a102.set_ylabel("Volume (USD)",color="darkorange")
                        a10.set_title("Annual Matched Activity Trend")
                        a10.legend(loc="upper left"); a102.legend(loc="upper right"); f10.tight_layout()
                        buf10=io.BytesIO(); f10.savefig(buf10,format="pdf",bbox_inches="tight"); buf10.seek(0)
                        zf.writestr("images/fig10_annual_trend.pdf",buf10.getvalue())
                        fig_names.append(("fig10_annual_trend","Annual trend of matched events and co-occurring volume"))
                        plt.close(f10)
                    except Exception: pass

                # Generate LaTeX figures snippet
                latex_lines = [
                    "% Auto-generated figure references for Overleaf",
                    "% Place PDF files in images/ folder",
                    "% Include with: \input{figures_include.tex}",
                    ""
                ]
                for fname, caption in fig_names:
                    latex_lines.append(f"\\begin{{figure}}[htbp]")
                    latex_lines.append(f"  \\centering")
                    latex_lines.append(f"  \\includegraphics[width=\\textwidth]{{images/{fname}.pdf}}")
                    latex_lines.append(f"  \\caption{{{caption}}}")
                    latex_lines.append(f"  \\label{{fig:{fname}}}")
                    latex_lines.append(f"\\end{{figure}}")
                    latex_lines.append("")
                zf.writestr("figures_include.tex","\n".join(latex_lines))

                # Generate figure index for the writing guide
                fig_index = "FIGURE INDEX\n============\n"
                for fname, caption in fig_names:
                    fig_index += f"- {fname}.pdf : {caption}\n"
                fig_index += f"\nTotal figures: {len(fig_names)}\n"
                fig_index += "\nAll figures are vector PDF, 300dpi, Type 42 fonts (compatible with IEEE/ACM templates).\n"
                fig_index += "Place the images/ folder in your Overleaf project root.\n"
                fig_index += "Use \\input{figures_include.tex} or copy individual \\includegraphics commands.\n"
                zf.writestr("17_figure_index.txt",fig_index)
                zf.writestr("01_dataset_stats.json",json.dumps(ds,indent=2,default=str))
                if not mdf6.empty:
                    zf.writestr("02_matching_stats.json",json.dumps(ms,indent=2,default=str))
                    zf.writestr("03_matched_pairs.csv",mdf6.to_csv(index=False))
                if gm3 is not None and not gm3.empty: zf.writestr("04_gang_metrics.csv",gm3.to_csv(index=False))
                if sdf2 is not None and not sdf2.empty: zf.writestr("05_sensitivity.csv",sdf2.to_csv(index=False))
                if not mdf6.empty:
                    ss2=mdf6.groupby("event_sector").agg(events=("event_victim","nunique"),pairs=("tx_hash","count"),vol=("tx_amountUSD","sum"),actors=("gang_normalized","nunique")).sort_values("vol",ascending=False).reset_index()
                    zf.writestr("06_sector_summary.csv",ss2.to_csv(index=False))
                    cs2=mdf6.groupby("event_country").agg(events=("event_victim","nunique"),pairs=("tx_hash","count"),vol=("tx_amountUSD","sum"),actors=("gang_normalized","nunique")).sort_values("vol",ascending=False).reset_index()
                    zf.writestr("07_country_summary.csv",cs2.to_csv(index=False))
                    ws2=mdf6.groupby("wallet_address").agg(family=("gang_normalized","first"),events=("event_date","nunique"),txs=("tx_hash","nunique"),vol=("tx_amountUSD","sum")).sort_values("events",ascending=False).reset_index()
                    zf.writestr("08_wallet_reuse.csv",ws2.to_csv(index=False))
                    td=mdf6[["gang_normalized","days_from_disclosure","temporal_phase","tx_amountUSD","event_sector","event_country"]].copy()
                    zf.writestr("09_timing_data.csv",td.to_csv(index=False))
                    ann2=mdf6.copy(); ann2["year"]=ann2["event_date"].dt.year
                    ay=ann2.groupby("year").agg(events=("event_victim","nunique"),pairs=("tx_hash","count"),vol=("tx_amountUSD","sum")).reset_index()
                    zf.writestr("10_annual_matched.csv",ay.to_csv(index=False))
                zf.writestr("11_registry_aligned.csv",reg_a.to_csv(index=False))
                tx_exp=tx_a.sample(min(100000,len(tx_a)),random_state=42) if len(tx_a)>100000 else tx_a
                zf.writestr("12_transactions_aligned.csv",tx_exp.to_csv(index=False))
                zf.writestr("13_gang_profiles.csv",gp.to_csv(index=False))
                am2=build_alias_map(gp); ad=pd.DataFrame(list(am2.items()),columns=["original","normalized"])
                zf.writestr("14_normalization_map.csv",ad.to_csv(index=False))
                meth=f"METHODOLOGY\n===========\nAnalysis period: {ov_s.date()} to {ov_e.date()}\nRegistry full: {r0.date()} to {r1.date()} ({len(reg)} events)\nTransactions full: {t0.date()} to {t1.date()} ({len(tx)} txs)\nAligned: {len(reg_a)} events, {len(tx_a)} txs\nExcluded: {len(reg)-len(reg_a)} events, {len(tx)-len(tx_a)} txs\n\nMatching: pre=30d, post=60d, tol=1d\nPhases: pre_disclosure / same_day / post_disclosure\nVolume types: event_level (with double-counting) vs deduplicated (unique tx hash)\n\nCAUTIONS:\n- No victim-level payment attribution\n- Temporal proximity != causality\n- Actor labels unstable (normalization best-effort)\n- Wallet data incomplete\n- Disclosure date may lag intrusion/negotiation/payment\n- Unmatched actors != no monetization\n- amountUSD depends on historical conversion\n\nTERMINOLOGY (use these):\n- public disclosure event\n- observed disclosure surface\n- actor-associated wallet\n- temporal co-occurrence\n- candidate monetization window\n- financial activity proxy\n- disclosure-to-transaction lag\n\nAVOID:\n- confirmed payment / victim paid\n- causal effect / direct attribution\n- proof of coordination\n\nRQs:\nRQ1: Temporal distribution of TX around disclosures\nRQ2: Recurring financial signatures (timing, volume, wallet reuse, bursts)\nRQ3: Sector/country concentration of matched events\nRQ4: Operational maturity vs TX behavior"
                zf.writestr("15_methodology.txt",meth)
                guide=f"PAPER WRITING GUIDE\n===================\nTitle: Following the Money: Temporal Co-occurrence Between Ransomware Disclosures and Actor-Associated Cryptocurrency Transactions\n\nSECTION -> DATA FILE:\n4.2 Data Collection -> 01_dataset_stats.json\n4.3 Preprocessing -> 14_normalization_map.csv\n4.4 Matching Method -> 15_methodology.txt\n5.1 Overview -> 01 + 11 + 12\n5.2 RQ1 (Temporal) -> 02_matching_stats.json + 09_timing_data.csv\n5.3 RQ2 (Gang patterns) -> 04_gang_metrics.csv\n5.4 RQ3 (Sector/Geo) -> 06 + 07\n5.5 Wallet reuse -> 08_wallet_reuse.csv\n5.6 Sensitivity -> 05_sensitivity.csv\n6. Threats -> 15_methodology.txt (CAUTIONS section)\n\nFIGURES (in images/ folder, all vector PDF):\nfig1_temporal_coverage.pdf -> Section 4.2 (Data Collection)\nfig2_timing_distribution.pdf -> Section 5.2 (RQ1)\nfig3_phase_by_actor.pdf -> Section 5.2 (RQ1)\nfig4_top_actors_volume.pdf -> Section 5.3 (RQ2)\nfig5_sector_volume.pdf -> Section 5.4 (RQ3)\nfig6_country_volume.pdf -> Section 5.4 (RQ3)\nfig7_sensitivity.pdf -> Section 5.6 (Robustness)\nfig8_events_vs_volume.pdf -> Section 5.3 (RQ2/RQ4)\nfig9_wallet_reuse.pdf -> Section 5.5 (Wallet Analysis)\nfig10_annual_trend.pdf -> Section 5.1 (Overview)\n\nLaTeX: use figures_include.tex for auto-generated figure environments.\nPlace images/ folder in Overleaf project root.\n\nRULES:\n- Every claim must cite specific numbers from files\n- Use cautious language: suggests, indicates, is associated with\n- Distinguish event-level volume from deduplicated volume\n- Acknowledge temporal alignment exclusions\n- Report sensitivity to show robustness\n- Reference figures using \\ref{{fig:figX_name}}"
                zf.writestr("16_writing_guide.txt",guide)
            buf.seek(0)
            st.download_button("Download Paper Data Package (ZIP)",buf,"paper_data_package.zip","application/zip")

    with tabs[8]:
        st.header("Raw Data Explorer")
        t2=st.selectbox("Table",["Registry (aligned)","Gang Profile","Wallets","Transactions (aligned)","Matched Pairs","Gang Metrics","Sensitivity"])
        if t2=="Registry (aligned)": st.dataframe(reg_a.head(500),use_container_width=True); st.download_button("CSV",reg_a.to_csv(index=False).encode(),"registry_aligned.csv")
        elif t2=="Gang Profile": st.dataframe(gp.head(300),use_container_width=True); st.download_button("CSV",gp.to_csv(index=False).encode(),"gang_profiles.csv")
        elif t2=="Wallets": st.dataframe(wal.head(500),use_container_width=True); st.download_button("CSV",wal.to_csv(index=False).encode(),"wallets.csv")
        elif t2=="Transactions (aligned)": st.dataframe(tx_a.head(500),use_container_width=True); st.download_button("CSV",tx_a.to_csv(index=False).encode(),"txs_aligned.csv")
        elif t2=="Matched Pairs":
            m2=st.session_state.get("mdf",pd.DataFrame())
            if m2.empty: st.info("Run Temporal Matching tab first.")
            else: st.dataframe(m2.head(500),use_container_width=True); st.download_button("CSV",m2.to_csv(index=False).encode(),"matched_pairs.csv")
        elif t2=="Gang Metrics":
            g2=st.session_state.get("gm",pd.DataFrame())
            if g2.empty: st.info("Run Gang Monetization tab first.")
            else: st.dataframe(g2,use_container_width=True); st.download_button("CSV",g2.to_csv(index=False).encode(),"gang_metrics.csv")
        elif t2=="Sensitivity":
            s3=st.session_state.get("sdf",pd.DataFrame())
            if s3.empty: st.info("Run Sensitivity tab first.")
            else: st.dataframe(s3,use_container_width=True); st.download_button("CSV",s3.to_csv(index=False).encode(),"sensitivity.csv")

    with tabs[9]:
        st.header("Data Quality")
        st.info(f"Aligned: {ov_s.strftime('%Y-%m-%d')} to {ov_e.strftime('%Y-%m-%d')}")
        c1,c2=st.columns(2)
        with c1:
            st.write("**Registry nulls:**"); rm2=reg_a.isnull().sum(); rm2=rm2[rm2>0]
            st.dataframe(rm2) if not rm2.empty else st.success("None")
        with c2:
            st.write("**TX nulls:**"); tm2=tx_a.isnull().sum(); tm2=tm2[tm2>0]
            st.dataframe(tm2) if not tm2.empty else st.success("None")
        c1,c2,c3=st.columns(3)
        c1.metric("Dup wallets",wal["address"].duplicated().sum() if "address" in wal.columns else 0)
        c2.metric("Dup TX hashes",tx_a["hash"].duplicated().sum() if "hash" in tx_a.columns else 0)
        c3.metric("Zero/neg amounts",int((tx_a["amountUSD"]<=0).sum()) if "amountUSD" in tx_a.columns else 0)
        rg2=set(reg_a["gang_normalized"].unique()); wf2=set(tx_a["family_normalized"].unique())
        c1b,c2b=st.columns(2)
        c1b.metric("Reg-only actors",len(rg2-wf2)); c2b.metric("Wallet-only families",len(wf2-rg2))
        st.write(f"Events excluded by alignment: **{len(reg)-len(reg_a):,}** (post {ov_e.strftime('%Y-%m-%d')})")
        st.write(f"TXs excluded by alignment: **{len(tx)-len(tx_a):,}** (pre {ov_s.strftime('%Y-%m-%d')})")

if __name__ == "__main__":
    main()
