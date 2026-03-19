import requests # type: ignore
import json

url = 'http://localhost:8000/predict'

normal_payload = {
    'features': {
        'src_port': 80, 'dst_port': 443, 'proto': 'tcp', 'service': '-', 'duration': 1.0,
        'src_bytes': 400, 'dst_bytes': 5000, 'missed_bytes': 0, 'src_pkts': 4, 'src_ip_bytes': 200,
        'dst_pkts': 5, 'dst_ip_bytes': 6000, 'dns_query': '-', 'dns_qclass': 0, 'dns_qtype': 0,
        'dns_rcode': 0, 'dns_AA': '-', 'dns_RD': '-', 'dns_RA': '-', 'dns_rejected': '-',
        'ssl_version': '-', 'ssl_cipher': '-', 'ssl_resumed': '-', 'ssl_established': '-',
        'ssl_subject': '-', 'ssl_issuer': '-', 'http_trans_depth': '-', 'http_method': '-',
        'http_uri': '-', 'http_version': '-', 'http_request_body_len': 0,
        'http_response_body_len': 0, 'http_user_agent': '-', 'http_orig_mime_types': '-',
        'http_resp_mime_types': '-', 'weird_addl': '-'
    }
}

attack_payload = {
    'features': {
        'src_port': 0, 'dst_port': 0, 'proto': 'icmp', 'service': '-', 'duration': 0,
        'src_bytes': 99999, 'dst_bytes': 0, 'missed_bytes': 0, 'src_pkts': 999, 'src_ip_bytes': 99999,
        'dst_pkts': 0, 'dst_ip_bytes': 0, 'dns_query': '-', 'dns_qclass': 0, 'dns_qtype': 0,
        'dns_rcode': 0, 'dns_AA': '-', 'dns_RD': '-', 'dns_RA': '-', 'dns_rejected': '-',
        'ssl_version': '-', 'ssl_cipher': '-', 'ssl_resumed': '-', 'ssl_established': '-',
        'ssl_subject': '-', 'ssl_issuer': '-', 'http_trans_depth': '-', 'http_method': '-',
        'http_uri': '-', 'http_version': '-', 'http_request_body_len': 0,
        'http_response_body_len': 0, 'http_user_agent': '-', 'http_orig_mime_types': '-',
        'http_resp_mime_types': '-', 'weird_addl': '-'
    }
}

with open("test_predict_out.txt", "w") as f:
    try:
        f.write("=== Test 1: Normal ===\n")
        r1 = requests.post(url, json=normal_payload, timeout=5)
        f.write(json.dumps(r1.json(), indent=2) + "\n\n")
    except Exception as e:
        f.write(str(e) + "\n\n")
        
    try:
        f.write("=== Test 2: Attack ===\n")
        r2 = requests.post(url, json=attack_payload, timeout=5)
        f.write(json.dumps(r2.json(), indent=2) + "\n")
    except Exception as e:
        f.write(str(e) + "\n")
