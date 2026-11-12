from typing import Any,Literal
from fastapi import APIRouter,HTTPException,Request
from pydantic import BaseModel,Field
from app import blueprint_records as records
from app.positive_learning import build_discovery_candidate
from app.capabilities import registry,resolve_capability
from app.signature_workflow import load_upstream_catalog,select_rules_for_detection
from app.readiness import evaluate_readiness

class Review(BaseModel):
    decision:Literal['accepted','rejected']
    reason:str=Field(min_length=1,max_length=2000)


def build_router(connect,get_job,get_profile,get_analysis,get_report=None):
    router=APIRouter()
    @router.post('/api/discovery/jobs/{job_id}/blueprints',status_code=201)
    async def create(job_id:str,request:Request):
        job=await get_job(job_id);profile=await get_profile(job_id);analysis=await get_analysis(job_id)
        hostname=(job.get('scope') or {}).get('hostname','')
        model,summary=build_discovery_candidate(hostname,job_id,profile,analysis,None)
        model=model.model_dump(mode='json')
        checks=(analysis.get('security_checks') or {}).get('checks',[])
        recommendations=[]
        for check in checks:
            cap=resolve_capability(check['check_id'])
            recommendations.append({'check_id':check['check_id'],'recommendation':check,
                'capability':cap,'status':'unresolved' if cap['status']=='unknown' else 'review',
                'proposed_actions':[],'missing':['Exact-build capability verification','Representative runtime validation']})
        catalog=load_upstream_catalog();selection=select_rules_for_detection(profile,analysis,catalog)
        fields=[]
        for ep in model.get('endpoints',[]):
            for f in ep.get('fields',[]):
                fields.append({'endpoint':ep['path_template'],'method':ep['method'],'field':f['name'],
                    'declared':None,'observed':f.get('shape'),
                    'inferred':f.get('proposed_constraints'),'reviewed':None,
                    'evidence':f.get('evidence',[]),
                    'readiness':evaluate_readiness({}),
                    'limitations':['Legacy samples do not prove independent sessions or roles']})
        report=await get_report(job_id) if get_report else None
        payload={'schema_version':'1.0.0','job_id':job_id,'model':model,'source_summary':summary,
            'fields':fields,'signature_selection':selection,'security_checks':recommendations,
            'run_evidence_report':report,
            'coverage':{'run_status':job.get('status'),'critical_complete':False,
                        'gaps':['Role coverage and independent-session counts require further evidence']},
            'catalog_fingerprint':selection.get('catalog_fingerprint'),
            'capability_registry_version':registry()['schema_version'],
            'review_status':'draft','deployment_authorized':False,'commands':[]}
        return records.append(connect,job_id,'blueprint',request.state.operator,payload)

    @router.get('/api/discovery/jobs/{job_id}/blueprints')
    async def listing(job_id:str):
        await get_job(job_id);return records.listing(connect,job_id)

    @router.get('/api/blueprints/{identifier}')
    def get(identifier:str):
        record=records.get(connect,identifier)
        if not record:raise HTTPException(404,'Blueprint not found')
        return record

    @router.get('/api/blueprints/{identifier}/export')
    def export(identifier:str):return get(identifier)

    @router.post('/api/blueprints/{identifier}/review',status_code=201)
    def review(identifier:str,body:Review,request:Request):
        current=get(identifier)
        payload={**current['payload'],'review_status':body.decision,'review_reason':body.reason,
                 'deployment_authorized':False}
        return records.append(connect,current['job_id'],'blueprint',request.state.operator,payload,identifier)
    return router
