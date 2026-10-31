"""Small, stable analyst-facing output, separate from detailed evidence contracts."""
from .common import atomic_json


def brief(bundle,manifest):
    review=bundle.get('ai_review',{})
    ai=review.get('result',{}) if review.get('status')=='completed' else {}
    return {
        'incident_id':bundle['incident_id'],
        'title':bundle['title'],
        'status':'Requires analyst review',
        'coverage':manifest.get('input_completeness','unknown'),
        'what_was_observed':[{'time':s['timestamp'],'action':s['summary'],
            'technique':s.get('technique_id'),'evidence_ids':s['evidence_ids'],
            'limitation':s['uncertainty_reason']} for s in bundle['steps']],
        'engine_connections':bundle['edges'],
        'ai_status':review.get('status','not_requested'),
        'ai_summary':ai.get('explanation'),
        'ai_assessment':ai.get('assessment'),
        'suggested_mappings':ai.get('technique_mappings',[]),
        'suggested_connections':ai.get('proposed_links',[]),
        'missing_evidence':ai.get('missing_evidence',[]),
        'limitations':bundle.get('uncertainties',[]),
        'important':'AI suggestions are unverified interpretations. Engine findings are not confirmation of compromise.',
    }


def write_brief(run,bundle,manifest):
    value=brief(bundle,manifest)
    atomic_json(run/'briefs'/f"{bundle['incident_id']}.json",value)
    return value
