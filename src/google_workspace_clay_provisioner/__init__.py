"""Automate sending domain and mailbox setup for Google Workspace and Clay.

Purpose-built for one stack: domains registered at Cloudflare, mailboxes hosted
on Google Workspace, campaigns run in Clay. It is not a general-purpose registrar
or DNS tool, and it targets no other mail host or sequencer.

Steps, in the order the CLI runs them:

1. Suggest available ``.com`` domains related to a seed domain.
2. Register the chosen domain with Cloudflare Registrar.
3. Add it to Google Workspace as a secondary domain and verify ownership.
4. Create the sending mailbox on the new domain.
5. Publish the MX, SPF, DKIM and DMARC records Google Workspace mail needs.
6. Verify all four records against public resolvers.
7. Prepare the Clay import (Clay has no API for this, see ``clay.py``).
"""

__version__ = "0.1.0"
