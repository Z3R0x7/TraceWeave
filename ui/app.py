import math
import os

import httpx
import plotly.graph_objects as go
import streamlit as st

API = os.getenv("API_URL", "http://127.0.0.1:8000")
st.set_page_config(page_title="Attack Investigation", page_icon="🔎", layout="wide")


def request(method, route, **kwargs):
    try:
        response = httpx.request(method, API + route, timeout=45, **kwargs)
        response.raise_for_status()
        return response
    except httpx.HTTPError:
        st.error("The application could not complete this request. Check API status and retry.")
        st.stop()
        raise RuntimeError("Request failed")


def get(route):
    return request("GET", route).json()


st.title("Attack Investigation")
st.caption("Trace findings to evidence, examine uncertainty, and investigate possible next targets.")
page = st.sidebar.radio("Workspace", ["Import", "Runs", "Incidents", "Investigation"])
if page == "Import":
    st.header("Import engine output")
    source = st.radio("Source", ["Local manifest", "HTTPS manifest"])
    value = st.text_input("Manifest path" if source == "Local manifest" else "Manifest URL",
                          type="default" if source == "Local manifest" else "password")
    if st.button("Start import", disabled=not value):
        remote = source == "HTTPS manifest"
        result = request("POST", "/api/v1/imports/" + ("remote" if remote else "local"),
                         json={"manifest_url" if remote else "manifest_path": value}).json()
        st.session_state["import_id"] = result["import_id"]
    if "import_id" in st.session_state:
        @st.fragment(run_every=2)
        def progress():
            result = get("/api/v1/imports/" + st.session_state["import_id"])
            st.write(f"Status: {result['status']} · Phase: {result['phase']}")
            st.caption(f"Transferred {result.get('processed_bytes', 0):,} bytes")
            if result["error"]:
                st.error(result["error"])
            if result["status"] == "completed":
                st.success("Import validated and ready for investigation.")
        progress()
elif page == "Runs":
    st.header("Imported runs")
    for run in get("/api/v1/runs"):
        manifest = run["manifest"]
        with st.expander(manifest["run_id"], expanded=True):
            st.write(manifest["source_dataset"])
            size_gib = manifest["source_dataset"]["source_size_bytes"] / 1024**3
            tier = {15: "Core", 30: "Advanced", 50: "Extreme"}.get(round(size_gib), "Custom")
            st.caption(f"Source tier: {tier} ({size_gib:.1f} GiB, engine metadata) · "
                       f"Engine status: {manifest['engine_status']}")
            st.write(f"Incidents: {manifest['incident_count']} · Imported: {run['imported_at']}")
            st.json(get(f"/api/v1/runs/{manifest['run_id']}/quality"))
elif page == "Incidents":
    runs = get("/api/v1/runs")
    if not runs:
        st.info("Import an engine-output manifest to begin.")
        st.stop()
    st.header("Incident list")
    run_id = st.selectbox("Run", [r["manifest"]["run_id"] for r in runs], key="inc_run")
    selected_manifest = next(r["manifest"] for r in runs if r["manifest"]["run_id"] == run_id)
    if selected_manifest["incident_count"] == 0:
        st.info("Processing completed successfully with zero detected incidents.")
        st.stop()
    base = f"/api/v1/runs/{run_id}"
    filters = st.columns(5)
    severity = filters[0].selectbox("Severity", ["all", "critical", "high", "medium", "low", "informational"], key="inc_sev")
    risk = filters[1].number_input("Minimum risk", 0, 100, 0, key="inc_risk")
    host = filters[2].text_input("Host", key="inc_host")
    account = filters[3].text_input("Account", key="inc_account")
    technique = filters[4].text_input("Technique ID", key="inc_tech")
    page_number = st.number_input("Incident page", min_value=1, value=1, key="inc_page")
    params = {"limit": 25, "offset": (page_number - 1) * 25, "min_risk": risk}
    params.update({k: v for k, v in {"severity": severity if severity != "all" else None,
                                  "host": host, "account": account,
                                  "technique": technique}.items() if v})
    collection = request("GET", base + "/incidents", params=params).json()
    st.caption(f"{collection['total']} matching incidents")
    st.dataframe(collection["items"], hide_index=True)
    if not collection["items"]:
        st.info("No incidents match the current filters or page.")
        st.stop()
    summaries = {i["incident_id"]: i for i in collection["items"]}
    chosen = st.selectbox("Select incident to investigate", list(summaries),
                          format_func=lambda i: f"{summaries[i]['title']} · {i}", key="inc_chosen")
    st.session_state["selected_incident"] = chosen
    st.session_state["selected_run"] = run_id
    st.info(f"Selected incident `{chosen}`. Switch to 'Investigation' in the sidebar to inspect.")
else:
    runs = get("/api/v1/runs")
    if not runs:
        st.info("Import an engine-output manifest to begin.")
        st.stop()
    st.header("Incident investigation")
    run_id = st.selectbox("Run", [r["manifest"]["run_id"] for r in runs], key="inv_run")
    selected_manifest = next(r["manifest"] for r in runs if r["manifest"]["run_id"] == run_id)
    if selected_manifest["incident_count"] == 0:
        st.info("Processing completed successfully with zero detected incidents.")
        st.stop()
    base = f"/api/v1/runs/{run_id}"
    collection = request("GET", base + "/incidents", params={"limit": 100}).json()
    if not collection["items"]:
        st.info("Processing completed successfully with zero detected incidents.")
        st.stop()
    summaries = {i["incident_id"]: i for i in collection["items"]}
    selected=st.session_state.get('selected_incident')
    if selected and st.session_state.get('selected_run')==run_id and selected not in summaries:
        detail=get(base+'/incidents/'+selected)
        summaries[selected]={'incident_id':selected,'title':detail['title']}
    default_idx = 0
    if "selected_incident" in st.session_state and st.session_state["selected_incident"] in summaries:
        default_idx = list(summaries).index(st.session_state["selected_incident"])
    identifier = str(st.selectbox("Incident", list(summaries), index=default_idx,
                                 format_func=lambda i: f"{summaries[i]['title']} · {i}"))
    st.session_state["selected_incident"] = identifier
    st.session_state["selected_run"] = run_id
    route = base + "/incidents/" + identifier
    incident = get(route)
    path = get(route + "/path")
    view = st.radio("Investigation view", ["Overview", "Timeline", "Graph", "Evidence",
                                          "Next targets", "Data quality", "Report"], horizontal=True)
    if view == "Overview":
        st.subheader(incident["title"])
        for limitation in incident.get('data_quality_impact',[]):
            if limitation.startswith(('Input coverage:','Excluded source bytes:')):st.caption(limitation)
        st.write(f"Severity: {incident['severity']} · Risk: {incident['risk_score']}")
        st.json(incident["techniques"])
        if incident.get("kill_chain"):
            st.write("Kill chain labels")
            st.json(incident["kill_chain"])
        if incident["engine_review"]:
            st.write("Engine review")
            review=incident['engine_review']
            result=review.get('result', review)
            st.caption('AI review: '+review.get('status','unknown')+' — suggestions require analyst verification')
            if result.get('explanation'):st.write(result['explanation'])
            if result.get('technique_mappings'):
                st.write('Suggested technique mappings')
                st.dataframe(result['technique_mappings'],use_container_width=True)
            if result.get('proposed_links'):
                st.write('Suggested connections — not confirmed attack edges')
                st.dataframe(result['proposed_links'],use_container_width=True)
            if result.get('missing_evidence'):
                st.write('Missing evidence')
                for gap in result['missing_evidence']:st.write('• '+gap)
            with st.expander('AI review details'):st.json(review)
    if view == "Timeline":
        st.caption("Timestamp ties and presentation order do not establish causality.")
        for step in path["timeline"]:
            with st.expander(f"{step['observed_at'] or 'Time unknown'} · {step['summary']}"):
                extra = f" · Phase: {step['kill_chain_phase']}" if step.get("kill_chain_phase") else ""
                st.write(f"{step['interpretation_status']} · Maliciousness: {step['maliciousness']}{extra}")
                st.write(f"Ordering: {step['ordering_basis']} ({step['ordering_confidence']})")
                st.code(", ".join(step["evidence_ids"]))
    if view == "Graph":
        eligible_nodes = [n for n in path["entities"] if n["type"] in {"host", "account", "ip", "process", "file", "event"}]
        nodes = eligible_nodes[:200]
        visible_ids = {n["entity_id"] for n in nodes}
        graph_edges = [e for e in path["relationships"]
                       if e["source_id"] in visible_ids and e["target_id"] in visible_ids][:500]
        if len(eligible_nodes) > 200 or len(path["relationships"]) > len(graph_edges):
            st.info("Graph shows up to 200 hosts/accounts and 500 relationships. "
                    "The timeline and relationship inspector retain all incident evidence.")
        positions = {n["entity_id"]: (math.cos(2 * math.pi * i / max(len(nodes), 1)),
                                      math.sin(2 * math.pi * i / max(len(nodes), 1)))
                     for i, n in enumerate(nodes)}
        fig = go.Figure()
        for edge in graph_edges:
            a, b = positions[edge["source_id"]], positions[edge["target_id"]]
            fig.add_trace(go.Scatter(x=[a[0], b[0]], y=[a[1], b[1]], mode="lines",
                line={"dash": {"observed": "solid", "derived": "dash", "hypothesized": "dot"}
                      [edge["interpretation_status"]]},
                name=edge["relationship_type"], text=", ".join(edge["evidence_ids"]),
                hoverinfo="name+text"))
            fig.add_annotation(x=b[0], y=b[1], ax=a[0], ay=a[1], xref="x", yref="y",
                               axref="x", ayref="y", showarrow=True, arrowhead=2)
        fig.add_trace(go.Scatter(x=[positions[n["entity_id"]][0] for n in nodes],
                                 y=[positions[n["entity_id"]][1] for n in nodes],
                                 text=[n["label"] for n in nodes], mode="markers+text",
                                 marker={"size": 18}, textposition="top center", name="Entities"))
        fig.update_layout(height=450, xaxis={"visible": False}, yaxis={"visible": False})
        st.plotly_chart(fig, width="stretch")
        if path["relationships"]:
            edge_id = st.selectbox("Inspect relationship", [e["relationship_id"]
                                                            for e in path["relationships"]])
            selected_edge = next(e for e in path["relationships"] if e["relationship_id"] == edge_id)
            st.json(selected_edge)
            edge_evidence = st.selectbox("Relationship evidence", selected_edge["evidence_ids"])
            st.json(request("GET", route + "/evidence", params={
                "evidence_id": edge_evidence
            }).json()["items"])
    if view == "Evidence":
        evidence_page = st.number_input("Evidence page", min_value=1, value=1)
        selected_ids = sorted({e for step in path["timeline"] for e in step["evidence_ids"]})
        selected = st.selectbox("Highlight timeline evidence", ["all"] + selected_ids)
        query: dict = {"limit": 100, "offset": (evidence_page - 1) * 100 if selected == "all" else 0}
        if selected != "all":
            query["evidence_id"] = selected
        rows = request("GET", route + "/evidence", params=query).json()["items"]
        for row in rows:
            if selected != "all" and row["evidence_id"] != selected:
                continue
            with st.expander(row["evidence_id"]):
                st.json(row)
    if view == "Next targets":
        result = get(route + "/reachability")
        st.info(result["message"])
        for candidate in result["candidates"]:
            with st.expander(candidate["target_id"]):
                st.json(candidate)
    if view == "Data quality":
        st.subheader("Dataset-wide quality")
        st.json(get(base + "/quality"))
        st.subheader("Incident-specific impact")
        for impact in incident["data_quality_impact"]:
            st.warning(impact)
        if not incident["data_quality_impact"]:
            st.write("No incident-specific impact supplied by the engine.")
    if view == "Report":
        if st.button("Check configured AI provider"):
            st.json(request("POST", "/api/v1/ai/health").json())
        if st.button("Generate report"):
            report = request("POST", route + "/report").json()
            st.json(report)
            md = request("GET", route + "/report.md").text
            html = request("GET", route + "/report.html").text
            st.download_button("Download Markdown", md, "incident.md", "text/markdown")
            st.download_button("Download HTML", html, "incident.html", "text/html")
