import asyncio
import os
from fastapi import APIRouter,HTTPException,Request
from app import blueprint_records as records
from app.ai_analysis import packet,analyze,validate_output
import json

tasks={}
lock=asyncio.Semaphore(1)


def build_router(connect,get_profile,get_analysis,get_report):
    router=APIRouter()
    @router.post('/api/discovery/jobs/{job_id}/ai-analysis',status_code=202)
    async def start(job_id:str,request:Request):
        model=os.getenv('WAF_AI_MODEL','').strip()
        base=os.getenv('WAF_AI_BASE_URL','http://host.docker.internal:11434')
        if not model:raise HTTPException(409,'Configure WAF_AI_MODEL for local Ollama analysis')
        profile=await get_profile(job_id);analysis=await get_analysis(job_id);report=await get_report(job_id)
        if (report.get('events') or [{}])[-1].get('status') in {'queued','running','resuming'}:raise HTTPException(409,'Wait for completed discovery before AI analysis')
        evidence=packet(profile,analysis.get('security_checks') or {},report.get('coverage') or {})
        actor=request.state.operator
        queued=records.append(connect,job_id,'ai_requested',actor,{'provider':'ollama','model':model,'read_only':True})
        async def work():
            try:
                async with lock: result=await analyze(evidence,base,model)
                await asyncio.to_thread(records.append,connect,job_id,'ai_result',actor,result,queued['id'])
            except Exception as error:
                await asyncio.to_thread(records.append,connect,job_id,'ai_failed',actor,
                    {'status':'failed','error_type':type(error).__name__,'message':'Local AI analysis failed; no application evidence or settings were modified'},queued['id'])
        task=asyncio.create_task(work());tasks[queued['id']]=task
        task.add_done_callback(lambda t:tasks.pop(queued['id'],None))
        return queued

    @router.get('/api/discovery/jobs/{job_id}/ai-analysis')
    async def results(job_id:str):
        await get_profile(job_id)
        items=await asyncio.to_thread(records.listing,connect,job_id)
        output=[]
        for row in items:
            if not row['kind'].startswith('ai_'):continue
            record=await asyncio.to_thread(records.get,connect,row['id'])
            if record['kind']=='ai_result':
                try:
                    # Revalidate older saved outputs before rendering; never present unsupported assertions.
                    record['payload']['analysis']=validate_output(json.dumps(record['payload']['analysis']),record['payload']['evidence_packet'])
                except Exception:
                    record['kind']='ai_failed';record['payload']={'message':'Saved AI result failed current evidence validation'}
            output.append(record)
        return output
    return router
