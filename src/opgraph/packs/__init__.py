"""Built-in technique packs. Register the ones you want explicitly:

    from opgraph.packs import core, net, web
    eng = Engagement(scope, techniques=[web, net, core])

Tools run on the engagement's executor (e.g. a Kali box over SSH): curl, nmap, ffuf.
Defaults are deliberately gentle (low thread counts and rates) so targets and the attack box stay healthy.
"""

from ._pinning import pinned_url

__all__ = ["pinned_url"]
