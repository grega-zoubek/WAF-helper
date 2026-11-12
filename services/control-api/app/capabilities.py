"""A capability cannot become runtime-verified from configuration expectations."""
import json
from pathlib import Path


def registry():
    return json.loads((Path(__file__).parent/'data/capabilities.json').read_text())


def resolve_capability(identifier, build=None):
    entry=next((x for x in registry()['entries'] if x['id']==identifier),None)
    if not entry: return {'id':identifier,'status':'unknown','supported_actions':[]}
    matches=bool(build and entry.get('verified_on',{}).get('build')==build)
    return {**entry,'status':'runtime_verified' if matches and entry['runtime_verified'] else 'unknown',
            'supported_actions':entry['supported_actions'] if matches and entry['runtime_verified'] else []}
