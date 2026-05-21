#!/usr/bin/env python3
import sys
from urllib.parse import quote

if len(sys.argv) != 2:
    print("Usage: python3 encode_id.py '<document_id>'")
    sys.exit(1)

doc_id = sys.argv[1]
print(quote(doc_id, safe=""))
