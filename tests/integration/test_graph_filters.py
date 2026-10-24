def test_graph_timeline_and_export_share_case_severity_and_time_filters(client, login_as):
    login_as("analyst")
    events = []
    for index, severity in enumerate(("high", "low")):
        response = client.post(
            "/api/events", json={"source": "graph-filter", "title": f"Scoped event {index}", "severity": severity, "event_time": f"2026-10-24T0{index}:00:00Z"}
        )
        assert response.status_code == 201
        events.append(response.json["id"])
    case_id = client.post("/api/incidents", json={"title": "Filtered graph case", "event_ids": events}).json["id"]
    for endpoint in ("graph", "graph/export", "timeline"):
        response = client.get(f"/api/visualizations/{endpoint}?case_id={case_id}&severity=high&start=2026-10-24T00:00:00Z&end=2026-10-24T00:30:00Z")
        assert response.status_code == 200
        items = response.json["items"] if endpoint == "timeline" else [node for node in response.json["nodes"] if node["type"] == "Event"]
        assert len(items) == 1
        assert (items[0]["id"] if endpoint == "timeline" else items[0]["reference_id"]) == events[0]
        assert client.get(f"/api/visualizations/{endpoint}?case_id=invalid").status_code == 422
        assert client.get(f"/api/visualizations/{endpoint}?severity=invalid").status_code == 422
        empty = client.get(f"/api/visualizations/{endpoint}?case_id=99999").json
        assert not (empty["items"] if endpoint == "timeline" else empty["nodes"])
