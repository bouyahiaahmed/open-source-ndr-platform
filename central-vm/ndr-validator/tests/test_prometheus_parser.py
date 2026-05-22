from app.prometheus_parser import parse_prometheus


def test_parse_prometheus_labels_and_values():
    text = '''
# HELP component_errors_total Errors
component_errors_total{component_id="dp",component_type="sink"} 3
vector_processed_events_total 12.5
'''
    samples = parse_prometheus(text)
    assert len(samples) == 2
    assert samples[0].name == "component_errors_total"
    assert samples[0].labels["component_id"] == "dp"
    assert samples[0].value == 3
