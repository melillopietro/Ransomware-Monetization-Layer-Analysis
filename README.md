# Ransomware Monetization Layer Analysis

## Overview

Streamlit-based analytical platform for correlating public ransomware
disclosure events with actor-associated cryptocurrency transaction records.

## Setup

Install dependencies from requirements.txt then run: streamlit run app.py

## Data Files

Place DATASETv3.xlsx and data.json in the project root.

## Tabs

1. Dataset Overview
2. Temporal Correlation Explorer
3. Gang-Level Monetization Patterns
4. Sector and Geography
5. Wallet Reuse and Transaction Network
6. Burst and Sensitivity Analysis
7. Paper Figures Export
8. Narrative Builder
9. Raw Data Explorer
10. Data Quality

## Research Questions

- RQ1: Temporal distribution of transactions around disclosures
- RQ2: Recurring financial signatures per actor
- RQ3: Sector/country concentration
- RQ4: Operational maturity vs transaction behavior

## Cautions

- Temporal proximity does not imply causality
- Actor labels are unstable
- Wallet data is incomplete
- No victim-level payment attribution
