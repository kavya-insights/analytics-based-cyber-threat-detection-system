import os
import re
import pandas as pd
import plotly.express as px
import streamlit as st

# ============================================================
# ANALYTICS BASED CYBER THREAT DETECTION SYSTEM
# Professional Python Data Analytics Dashboard
# ============================================================

st.set_page_config(
    page_title="Cyber Threat Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# PROJECT DIRECTORY
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_FILES = [
    os.path.join(BASE_DIR, "data", "cyber_threat_data.csv"),
    os.path.join(BASE_DIR, "cyber_threat_data.csv"),
]

# ============================================================
# DATASET COLUMN NAMES
# ============================================================

TOTAL = "Total Cyber Crimes (IT Act + IPC r/w IT Act + SLL r/w IT Act)"
IT_ACT = "Total Offences under I.T. Act"
IPC = "Total Offences under IPC"
SLL = "Total Offences under SLL"

# ============================================================
# THREAT CATEGORY MAPPING
# ============================================================

CATEGORY_MAP = {
    "Ransomware":
        "A. Offences under I.T. Act - Computer Related Offences - Computer Related Offences (Sec.66) - a1) Ransom-ware",

    "Identity Theft":
        "A. Offences under I.T. Act - Computer Related Offences - C) Identity Theft (Sec.66C)",

    "Cyber Terrorism":
        "A. Offences under I.T. Act - Cyber Terrorism (Sec.66 F)",

    "Cyber Stalking/Bullying":
        "Cyber Stalking/ Bullying of Women/ Children (Sec.354D IPC)",

    "Data Theft":
        "Data theft (Sec.379 to 381)",

    "Credit/Debit Card Fraud":
        "Fraud (Sec.420 r/w Sec.465, 468- 471 IPC) - A) Credit Card/Debit Card",

    "ATM Fraud":
        "B. IPC Crimes(Involving Communication Devices as Medium/Target or r/w IT Act) - Fraud (Sec.420 r/w Sec.465, 468- 471 IPC) - B) ATMs",

    "Online Banking Fraud":
        "B. IPC Crimes(Involving Communication Devices as Medium/Target or r/w IT Act) - Fraud (Sec.420 r/w Sec.465, 468- 471 IPC) - C) Online Banking Fraud",

    "OTP Fraud":
        "B. IPC Crimes(Involving Communication Devices as Medium/Target or r/w IT Act) - Fraud (Sec.420 r/w Sec.465, 468- 471 IPC) - D) OTP Frauds",

    "Cyber Blackmailing/Threatening":
        "B. IPC Crimes(Involving Communication Devices as Medium/Target or r/w IT Act) - Cyber Blackmailing/ Threatening (Sec.506,503,384 IPC)",

    "Fake Profile":
        "B. IPC Crimes(Involving Communication Devices as Medium/Target or r/w IT Act) - Fake Profile (r/w IPC/SLL)",

    "Fake News":
        "B. IPC Crimes(Involving Communication Devices as Medium/Target or r/w IT Act) - Fake News on Social Media (Sec.505)",

    "Online Gambling":
        "C. Offences under SLL (Involving Communication Devices as Medium/ Target) r/w IT Act - Gambling Act (Online Gambling)",
}

# ============================================================
# LOAD DATA
# ============================================================

@st.cache_data
def load_data():
    data_file = None

    for file_path in DATA_FILES:
        if os.path.exists(file_path):
            data_file = file_path
            break

    if data_file is None:
        raise FileNotFoundError(
            "cyber_threat_data.csv was not found.\n\n"
            "Put your CSV file here:\n"
            "data/cyber_threat_data.csv"
        )

    df = pd.read_csv(data_file)

    # Clean column names
    df.columns = [
        re.sub(r"\s+", " ", str(col).strip())
        for col in df.columns
    ]

    # Find State/UT column
    state_column = None

    for col in df.columns:
        cleaned = col.strip().lower()
        if cleaned in {"state/ut", "state / ut", "state", "state/ut name"}:
            state_column = col
            break

    if state_column is None:
        raise ValueError(
            "The dataset does not contain a State/UT column."
        )

    if state_column != "State/UT":
        df.rename(columns={state_column: "State/UT"}, inplace=True)

    # Clean state names
    df["State/UT"] = (
        df["State/UT"]
        .astype(str)
        .str.strip()
    )

    # Remove empty rows/columns
    df = df.dropna(axis=0, how="all")
    df = df.dropna(axis=1, how="all")

    # Remove duplicate rows
    df = df.drop_duplicates()

    # Remove aggregate rows
    aggregate_labels = {
        "total all india",
        "total state(s)",
        "total state",
        "all india",
        "total",
        "nan",
    }

    df = df[
        ~df["State/UT"].str.lower().isin(aggregate_labels)
    ].copy()

    # Convert non-state columns to numbers
    for col in df.columns:
        if col != "State/UT":
            df[col] = pd.to_numeric(
                df[col],
                errors="coerce"
            ).fillna(0)

    return df


# ============================================================
# LOAD DATA SAFELY
# ============================================================

try:
    df = load_data()
except Exception as error:
    st.error("❌ Could not load the cyber threat dataset.")
    st.code(str(error))
    st.info(
        "Required structure:\n\n"
        "app.py\n"
        "data/\n"
        "    cyber_threat_data.csv"
    )
    st.stop()

# ============================================================
# REQUIRED MAIN COLUMNS
# ============================================================

for column in [IT_ACT, IPC, SLL]:
    if column not in df.columns:
        df[column] = 0

# Create total only if it is absent
if TOTAL not in df.columns:
    df[TOTAL] = df[IT_ACT] + df[IPC] + df[SLL]

# ============================================================
# AVAILABLE THREAT CATEGORIES
# ============================================================

available_categories = {
    name: column
    for name, column in CATEGORY_MAP.items()
    if column in df.columns
}

# ============================================================
# THREAT SUMMARY
# ============================================================

if available_categories:
    cat_df = pd.DataFrame({
        "Threat": list(available_categories.keys()),
        "Cases": [
            df[column].sum()
            for column in available_categories.values()
        ],
    }).sort_values("Cases", ascending=False)
else:
    cat_df = pd.DataFrame(columns=["Threat", "Cases"])

# ============================================================
# HIGH-IMPACT THREATS
# ============================================================

high_impact_names = [
    "Ransomware",
    "Identity Theft",
    "Online Banking Fraud",
    "OTP Fraud",
    "Credit/Debit Card Fraud",
    "Data Theft",
]

high_impact_columns = [
    available_categories[name]
    for name in high_impact_names
    if name in available_categories
]

if high_impact_columns:
    df["High Impact Crimes"] = df[high_impact_columns].sum(axis=1)
else:
    df["High Impact Crimes"] = 0

# ============================================================
# MIN-MAX NORMALIZATION
# ============================================================

def minmax(series):
    if series.max() == series.min():
        return pd.Series(0.0, index=series.index)

    return (
        (series - series.min())
        / (series.max() - series.min())
        * 100
    )

# ============================================================
# NATIONAL SHARE
# ============================================================

total_crimes = df[TOTAL].sum()

if total_crimes == 0:
    df["Cybercrime Share %"] = 0.0
else:
    df["Cybercrime Share %"] = (
        df[TOTAL] / total_crimes * 100
    )

# ============================================================
# PROJECT ANALYTICAL RISK SCORE
# ============================================================

df["Total Crime Score"] = minmax(df[TOTAL])
df["High Impact Score"] = minmax(df["High Impact Crimes"])

df["Cyber Threat Risk Score"] = (
    df["Total Crime Score"] * 0.70
    + df["High Impact Score"] * 0.30
).round(2)

df["Risk Level"] = pd.cut(
    df["Cyber Threat Risk Score"],
    bins=[-1, 25, 50, 75, 100],
    labels=["Low", "Medium", "High", "Critical"],
)

# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🛡️ Cyber Threat Analytics")
st.sidebar.caption("Professional Data Analytics Dashboard")

theme = st.sidebar.radio(
    "🎨 Dashboard Theme",
    ["Dark", "Light"],
    horizontal=True,
)

# ============================================================
# THEME
# ============================================================

if theme == "Dark":
    background = "#0b1020"
    card = "#111827"
    text = "#f8fafc"
    muted = "#cbd5e1"
    border = "#263244"
    plot_template = "plotly_dark"
else:
    background = "#f5f7fb"
    card = "#ffffff"
    text = "#111827"
    muted = "#475467"
    border = "#d0d5dd"
    plot_template = "plotly_white"

# ============================================================
# CSS
# ============================================================

st.markdown(
    f"""
    <style>
    .stApp {{
        background: {background};
    }}

    .block-container {{
        max-width: 1450px;
        padding-top: 1.5rem;
        padding-bottom: 2.5rem;
    }}

    [data-testid="stMetric"] {{
        background: {card};
        border: 1px solid {border};
        border-radius: 14px;
        padding: 16px;
    }}

    [data-testid="stMetricLabel"] {{
        color: {muted} !important;
    }}

    [data-testid="stMetricValue"] {{
        color: {text} !important;
    }}

    div[data-testid="stSidebar"] {{
        background: {card};
    }}

    div[data-testid="stSidebar"] * {{
        color: {text} !important;
    }}

    h1, h2, h3 {{
        color: {text} !important;
    }}

    .project-box {{
        background: {card};
        border: 1px solid {border};
        border-radius: 14px;
        padding: 18px;
        margin-top: 10px;
        margin-bottom: 10px;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# NAVIGATION
# ============================================================

st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Executive Dashboard",
        "📊 State Intelligence",
        "🛡️ Threat Intelligence",
        "🔥 Risk Intelligence",
        "📋 Data Explorer",
        "ℹ️ Project",
    ],
)

st.sidebar.divider()

st.sidebar.caption("Python • Pandas • Plotly • Streamlit")
st.sidebar.caption(f"{len(df)} State/UT records loaded")

# ============================================================
# HERO
# IMPORTANT: NO HTML HERE
# ============================================================

st.title("🛡️ Analytics Based Cyber Threat Detection System")

st.write(
    "Interactive cybercrime intelligence dashboard for "
    "state-level patterns, fraud, threat analysis and "
    "analytical risk assessment."
)

st.divider()

# ============================================================
# EXECUTIVE DASHBOARD
# ============================================================

if page == "🏠 Executive Dashboard":

    total = df[TOTAL].sum()
    average = df[TOTAL].mean()

    highest = df.loc[df[TOTAL].idxmax()]
    highest_risk = df.loc[df["Cyber Threat Risk Score"].idxmax()]

    critical = int(
        (df["Risk Level"].astype(str) == "Critical").sum()
    )

    st.header("🏠 Executive Dashboard")

    # KPIs
    k1, k2, k3, k4, k5 = st.columns(5)

    k1.metric("Total Cyber Crimes", f"{total:,.0f}")
    k2.metric("States / UTs", f"{len(df)}")
    k3.metric("Average / State", f"{average:,.0f}")
    k4.metric("Highest Volume", str(highest["State/UT"]))
    k5.metric("Critical Risk States", str(critical))

    # State chart
    st.subheader("📈 State-Level Cybercrime Overview")

    state_data = (
        df[["State/UT", TOTAL]]
        .sort_values(TOTAL)
    )

    fig = px.bar(
        state_data,
        x=TOTAL,
        y="State/UT",
        orientation="h",
        text=TOTAL,
        title="Cybercrime Volume by State / UT",
        template=plot_template,
    )

    fig.update_traces(
        texttemplate="%{text:,.0f}",
        textposition="outside",
    )

    fig.update_layout(
        height=max(650, len(df) * 22),
        margin=dict(l=10, r=50, t=65, b=10),
    )

    st.plotly_chart(fig, use_container_width=True)

    # Two charts
    left, right = st.columns(2)

    with left:
        st.subheader("🔥 Leading Threat Categories")

        top = (
            cat_df.head(10)
            .sort_values("Cases")
        )

        if not top.empty:
            fig = px.bar(
                top,
                x="Cases",
                y="Threat",
                orientation="h",
                text="Cases",
                title="Top Selected Cybercrime Categories",
                template=plot_template,
            )

            fig.update_traces(
                texttemplate="%{text:,.0f}",
                textposition="outside",
            )

            fig.update_layout(height=520)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat categories found in this dataset.")

    with right:
        st.subheader("⚖️ Crime Group Composition")

        groups = pd.DataFrame({
            "Crime Group": ["IT Act", "IPC", "SLL"],
            "Cases": [
                df[IT_ACT].sum(),
                df[IPC].sum(),
                df[SLL].sum(),
            ],
        })

        fig = px.pie(
            groups,
            names="Crime Group",
            values="Cases",
            hole=0.52,
            title="IT Act vs IPC vs SLL",
            template=plot_template,
        )

        fig.update_layout(height=520)
        st.plotly_chart(fig, use_container_width=True)

    # Insights
    st.subheader("💡 Executive Insights")

    if not cat_df.empty:
        top_threat = cat_df.iloc[0]
        top_threat_text = (
            f"{top_threat['Threat']} is the largest available "
            f"threat category with {top_threat['Cases']:,.0f} cases."
        )
    else:
        top_threat_text = "No threat category is available."

    fraud_names = [
        "OTP Fraud",
        "Online Banking Fraud",
        "Credit/Debit Card Fraud",
        "ATM Fraud",
    ]

    fraud_total = cat_df[
        cat_df["Threat"].isin(fraud_names)
    ]["Cases"].sum()

    st.info(
        f"🔎 {highest['State/UT']} has the highest reported "
        f"cybercrime volume at {highest[TOTAL]:,.0f} cases."
    )

    st.info(f"🔥 {top_threat_text}")

    st.info(
        f"💳 Selected digital fraud categories account for "
        f"{fraud_total:,.0f} cases."
    )

    st.info(
        f"⚠️ {highest_risk['State/UT']} has the highest "
        f"project-specific analytical risk score of "
        f"{highest_risk['Cyber Threat Risk Score']:.2f}."
    )

# ============================================================
# STATE INTELLIGENCE
# ============================================================

elif page == "📊 State Intelligence":

    st.header("📊 State Intelligence")

    states = sorted(
        df["State/UT"]
        .dropna()
        .unique()
        .tolist()
    )

    state = st.selectbox(
        "Select a State / UT",
        states,
    )

    row = df[df["State/UT"] == state].iloc[0]

    a, b, c, d = st.columns(4)

    a.metric("Cyber Crimes", f"{row[TOTAL]:,.0f}")
    b.metric("Risk Score", f"{row['Cyber Threat Risk Score']:.2f}")
    c.metric("Risk Level", str(row["Risk Level"]))
    d.metric("National Share", f"{row['Cybercrime Share %']:.2f}%")

    state_cat = pd.DataFrame({
        "Threat": list(available_categories.keys()),
        "Cases": [
            row[column]
            for column in available_categories.values()
        ],
    }).sort_values("Cases", ascending=False)

    left, right = st.columns(2)

    with left:
        st.subheader(f"🔥 Top Threat Categories — {state}")

        top_state = (
            state_cat.head(10)
            .sort_values("Cases")
        )

        if not top_state.empty:
            fig = px.bar(
                top_state,
                x="Cases",
                y="Threat",
                orientation="h",
                text="Cases",
                title=f"Top Threat Categories — {state}",
                template=plot_template,
            )

            fig.update_traces(
                texttemplate="%{text:,.0f}",
                textposition="outside",
            )

            fig.update_layout(height=600)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat data available.")

    with right:
        st.subheader(f"⚖️ Crime Group Mix — {state}")

        groups = pd.DataFrame({
            "Crime Group": ["IT Act", "IPC", "SLL"],
            "Cases": [
                row[IT_ACT],
                row[IPC],
                row[SLL],
            ],
        })

        fig = px.pie(
            groups,
            names="Crime Group",
            values="Cases",
            hole=0.5,
            title=f"Crime Group Mix — {state}",
            template=plot_template,
        )

        fig.update_layout(height=600)
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("🏆 State Ranking by Cybercrime Volume")

    ranking = (
        df[
            [
                "State/UT",
                TOTAL,
                "Cyber Threat Risk Score",
                "Risk Level",
            ]
        ]
        .copy()
        .sort_values(TOTAL, ascending=False)
    )

    ranking.insert(
        0,
        "Rank",
        range(1, len(ranking) + 1),
    )

    st.dataframe(
        ranking,
        use_container_width=True,
        hide_index=True,
    )

# ============================================================
# THREAT INTELLIGENCE
# ============================================================

elif page == "🛡️ Threat Intelligence":

    st.header("🛡️ Threat Intelligence")

    if cat_df.empty:
        st.warning("No threat category columns were found.")
    else:

        selected = st.multiselect(
            "Choose threat categories",
            cat_df["Threat"].tolist(),
            default=cat_df.head(min(7, len(cat_df)))["Threat"].tolist(),
        )

        if selected:
            chosen = cat_df[
                cat_df["Threat"].isin(selected)
            ]

            fig = px.bar(
                chosen.sort_values("Cases"),
                x="Cases",
                y="Threat",
                orientation="h",
                text="Cases",
                title="Selected Threat Categories",
                template=plot_template,
            )

            fig.update_traces(
                texttemplate="%{text:,.0f}",
                textposition="outside",
            )

            fig.update_layout(height=600)
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("💳 Digital Fraud")

        fraud = cat_df[
            cat_df["Threat"].isin([
                "OTP Fraud",
                "Online Banking Fraud",
                "Credit/Debit Card Fraud",
                "ATM Fraud",
            ])
        ]

        if not fraud.empty:
            fig = px.bar(
                fraud,
                x="Threat",
                y="Cases",
                text="Cases",
                title="Digital Fraud Comparison",
                template=plot_template,
            )

            fig.update_traces(
                texttemplate="%{text:,.0f}",
                textposition="outside",
            )

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No digital fraud columns are available.")

        st.subheader("🔐 High-Impact Threats")

        high = cat_df[
            cat_df["Threat"].isin([
                "Identity Theft",
                "Ransomware",
                "Data Theft",
                "Cyber Terrorism",
                "Cyber Blackmailing/Threatening",
            ])
        ]

        if not high.empty:
            fig = px.bar(
                high,
                x="Threat",
                y="Cases",
                text="Cases",
                title="High-Impact Cyber Threats",
                template=plot_template,
            )

            fig.update_traces(
                texttemplate="%{text:,.0f}",
                textposition="outside",
            )

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No high-impact threat columns are available.")

# ============================================================
# RISK INTELLIGENCE
# ============================================================

elif page == "🔥 Risk Intelligence":

    st.header("🔥 Risk Intelligence")

    st.warning(
        "The Cyber Threat Risk Score is a project-specific "
        "analytical metric. It is not an official government "
        "classification."
    )

    risk = (
        df[
            [
                "State/UT",
                TOTAL,
                "High Impact Crimes",
                "Cybercrime Share %",
                "Cyber Threat Risk Score",
                "Risk Level",
            ]
        ]
        .sort_values(
            "Cyber Threat Risk Score",
            ascending=False,
        )
    )

    left, right = st.columns(2)

    with left:
        top_risk = (
            risk.head(10)
            .sort_values("Cyber Threat Risk Score")
        )

        fig = px.bar(
            top_risk,
            x="Cyber Threat Risk Score",
            y="State/UT",
            orientation="h",
            text="Cyber Threat Risk Score",
            title="Top 10 Analytical Risk Scores",
            template=plot_template,
        )

        fig.update_traces(
            texttemplate="%{text:.2f}",
            textposition="outside",
        )

        fig.update_layout(height=620)
        st.plotly_chart(fig, use_container_width=True)

    with right:
        counts = (
            df["Risk Level"]
            .astype(str)
            .value_counts()
            .reindex(["Low", "Medium", "High", "Critical"])
            .fillna(0)
            .reset_index()
        )

        counts.columns = ["Risk Level", "States"]

        fig = px.pie(
            counts,
            names="Risk Level",
            values="States",
            hole=0.5,
            title="Analytical Risk Level Distribution",
            template=plot_template,
        )

        fig.update_layout(height=620)
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("📋 Complete Risk Ranking")

    st.dataframe(
        risk,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "⬇️ Download Risk Analysis CSV",
        risk.to_csv(index=False).encode("utf-8"),
        "cyber_threat_risk_analysis.csv",
        "text/csv",
    )

# ============================================================
# DATA EXPLORER
# ============================================================

elif page == "📋 Data Explorer":

    st.header("📋 Data Explorer")

    col1, col2 = st.columns([2, 1])

    with col1:
        search = st.text_input("🔎 Search State / UT")

    with col2:
        max_rows = st.number_input(
            "Rows to display",
            min_value=5,
            max_value=max(5, len(df)),
            value=min(50, max(5, len(df))),
            step=5,
        )

    shown = df.copy()

    if search:
        shown = shown[
            shown["State/UT"].str.contains(
                search,
                case=False,
                na=False,
            )
        ]

    st.write(
        f"Showing **{len(shown)}** matching records."
    )

    st.dataframe(
        shown.head(int(max_rows)),
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "⬇️ Download Filtered Dataset",
        shown.to_csv(index=False).encode("utf-8"),
        "cyber_threat_filtered_data.csv",
        "text/csv",
    )

# ============================================================
# PROJECT INFORMATION
# ============================================================

elif page == "ℹ️ Project":

    st.header("ℹ️ Project Overview")

    st.subheader("🛡️ Analytics Based Cyber Threat Detection System")

    st.write(
        "This project uses real-world cybercrime data to "
        "discover patterns, compare States/UTs, analyze "
        "fraud and high-impact threats, and communicate "
        "findings through an interactive analytics dashboard."
    )

    st.subheader("📊 Data Analytics Workflow")

    st.info(
        "Raw Dataset → Data Cleaning → Exploratory Analysis → "
        "Threat Analysis → Risk Score → Interactive Dashboard"
    )

    st.subheader("🛠️ Technologies")

    st.write(
        "Python • Pandas • NumPy • Plotly • Streamlit"
    )

    st.subheader("📌 Project Features")

    features = [
        "State-level cybercrime analysis",
        "Threat category analysis",
        "Digital fraud analysis",
        "IT Act / IPC / SLL comparison",
        "Project-specific analytical risk scoring",
        "Interactive state selection",
        "Searchable dataset",
        "CSV downloads",
        "Dark and Light dashboard themes",
    ]

    for feature in features:
        st.write(f"✅ {feature}")

    st.subheader("⚠️ Important")

    st.warning(
        "The Cyber Threat Risk Score is an analytical metric "
        "created specifically for this project. It should not "
        "be presented as an official government risk classification."
    )

# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🛡️ Analytics Based Cyber Threat Detection System "
    "• Python Data Analytics Portfolio Project"
)
