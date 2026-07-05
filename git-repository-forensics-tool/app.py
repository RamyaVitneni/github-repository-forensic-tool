from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer.git_collector import GitRepositoryError
from analyzer.report_generator import generate_pdf_report
from analyzer.scanner import scan_repository


st.set_page_config(
    page_title="Git Repository Forensics Tool",
    page_icon="🕵️",
    layout="wide",
)

st.title("🕵️ Git Repository Forensics and Insider Code Tampering Investigation Tool")
st.caption("Analyze GitHub repository history for secrets, deleted sensitive files, suspicious commits, author mismatch, and risk scoring.")

with st.sidebar:
    st.header("Scan Configuration")
    investigator_name = st.text_input("Investigator Name", value="Ramya")
    repo_path = st.text_input(
        "GitHub Repository URL",
        placeholder="Example: https://github.com/owner/repository",
        help="Paste a public GitHub repository URL. Local paths are also supported for testing.",
    )
    scan_clicked = st.button("Start Forensic Scan", type="primary")

    st.divider()
    st.subheader("Input Help")
    st.write("Use a public GitHub URL, for example:")
    st.code("https://github.com/owner/repository")
    st.write("For offline testing, you can still create and scan a local demo repository:")
    st.code("python scripts/create_test_repo.py")


def severity_sort_key(severity: str) -> int:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    return order.get(severity, 0)


if scan_clicked:
    if not repo_path.strip():
        st.error("Please enter a GitHub repository URL.")
    else:
        try:
            with st.spinner("Analyzing Git repository history..."):
                result = scan_repository(repo_path.strip(), investigator_name.strip() or "Investigator")

            st.success("Forensic scan completed successfully.")

            metrics = result["metrics"]
            summary = result["summary"]
            findings = result["findings"]
            commits = result["commits"]

            st.subheader("Case Summary")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Case ID", result["case_id"])
            col2.metric("Repository", summary["repo_name"])
            col3.metric("Branch", summary["active_branch"])
            col4.metric("Source", summary.get("source_type", "Local Path"))

            if summary.get("source_url"):
                st.write(f"**GitHub URL:** {summary['source_url']}")
            st.write(f"**Analyzed local copy:** `{summary['repo_path']}`")

            st.subheader("Forensic Metrics")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Commits", metrics["total_commits_analyzed"])
            c2.metric("Contributors", metrics["total_contributors"])
            c3.metric("Total Findings", metrics["total_findings"])
            c4.metric("Suspicious Commits", metrics["suspicious_commits"])

            c5, c6, c7 = st.columns(3)
            c5.metric("Secrets Detected", metrics["secrets_detected"])
            c6.metric("Deleted Sensitive Files", metrics["deleted_sensitive_files"])
            c7.metric("High Risk Findings", metrics["high_risk_findings"])

            findings_df = pd.DataFrame(findings)
            commits_df = pd.DataFrame(
                [
                    {
                        "commit_hash": c["short_hash"],
                        "author_name": c["author_name"],
                        "author_email": c["author_email"],
                        "commit_date": c["commit_date"],
                        "commit_message": c["commit_message"],
                        "files_changed_count": c["files_changed_count"],
                        "lines_added": c["lines_added"],
                        "lines_deleted": c["lines_deleted"],
                    }
                    for c in commits
                ]
            )

            tab1, tab2, tab3, tab4 = st.tabs(["Findings", "Timeline", "Charts", "Report"])

            with tab1:
                st.subheader("Detected Forensic Findings")
                if findings_df.empty:
                    st.info("No suspicious findings detected.")
                else:
                    severity_filter = st.multiselect(
                        "Filter by Severity",
                        options=["Critical", "High", "Medium", "Low"],
                        default=["Critical", "High", "Medium", "Low"],
                    )
                    filtered_df = findings_df[findings_df["severity"].isin(severity_filter)]
                    st.dataframe(
                        filtered_df[
                            [
                                "severity",
                                "risk_score",
                                "finding_type",
                                "commit_hash",
                                "author_name",
                                "author_email",
                                "commit_date",
                                "file_path",
                                "evidence",
                                "recommendation",
                            ]
                        ],
                        use_container_width=True,
                    )

            with tab2:
                st.subheader("Commit Timeline Reconstruction")
                st.dataframe(commits_df, use_container_width=True)

            with tab3:
                st.subheader("Visual Analysis")
                if not findings_df.empty:
                    severity_counts = findings_df.groupby("severity").size().reset_index(name="count")
                    severity_counts["order"] = severity_counts["severity"].apply(severity_sort_key)
                    severity_counts = severity_counts.sort_values("order", ascending=False)
                    fig1 = px.bar(severity_counts, x="severity", y="count", title="Findings by Severity")
                    st.plotly_chart(fig1, use_container_width=True)

                    type_counts = findings_df.groupby("finding_type").size().reset_index(name="count")
                    fig2 = px.bar(type_counts, x="finding_type", y="count", title="Findings by Type")
                    fig2.update_layout(xaxis_tickangle=-35)
                    st.plotly_chart(fig2, use_container_width=True)

                if not commits_df.empty:
                    contributor_activity = commits_df.groupby("author_email").size().reset_index(name="commits")
                    fig3 = px.pie(contributor_activity, names="author_email", values="commits", title="Contributor Activity")
                    st.plotly_chart(fig3, use_container_width=True)

            with tab4:
                st.subheader("Generate Investigation Report")
                pdf_path = generate_pdf_report(result)
                st.success(f"PDF report generated: {pdf_path}")
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        "Download PDF Report",
                        data=f,
                        file_name=Path(pdf_path).name,
                        mime="application/pdf",
                    )

                if not findings_df.empty:
                    csv_data = findings_df.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        "Download Findings CSV",
                        data=csv_data,
                        file_name=f"{result['case_id']}_findings.csv",
                        mime="text/csv",
                    )

        except GitRepositoryError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.exception(exc)
else:
    st.info("Enter a public GitHub repository URL from the sidebar and click **Start Forensic Scan**.")

    st.subheader("What this tool detects")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        **Secret Leakage**
        - Passwords
        - API keys
        - Tokens
        - Private keys
        - Database URLs
        """)
    with col2:
        st.markdown("""
        **Sensitive File Activity**
        - `.env`
        - `credentials.txt`
        - `secrets.json`
        - `private.key`
        - Deleted sensitive files
        """)
    with col3:
        st.markdown("""
        **Insider Tampering Indicators**
        - Auth code changes
        - Large deletions
        - Suspicious messages
        - Author mismatch
        - Personal email commits
        """)
