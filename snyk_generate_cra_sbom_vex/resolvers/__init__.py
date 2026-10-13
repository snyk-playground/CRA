"""One module per source type (org, target, asset, project, group, tag).

Each exposes a resolve(...) function returning a list of
base.ResolvedProject, so discovery.py can treat every source type
interchangeably regardless of which of the six CLI flags supplied it
(requirements doc §8.3).
"""
