"""Provision a cold-email sending domain end to end.

Steps, in the order the CLI runs them:

1. Suggest available ``.com`` domains related to a seed domain.
2. Register the chosen domain with Cloudflare Registrar.
3. Add it to Google Workspace as a secondary domain and verify ownership.
4. Create the sending mailbox on the new domain.
5. Publish MX, SPF, DKIM and DMARC records in Cloudflare DNS.
6. Verify all four records against public resolvers.
7. Prepare the Clay import (Clay has no API for this — see ``clay.py``).
"""

__version__ = "0.1.0"
