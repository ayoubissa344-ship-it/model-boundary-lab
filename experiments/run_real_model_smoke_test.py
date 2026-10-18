#!/usr/bin/env python3
"""Optional local inference smoke test; does not test isolation or confidentiality."""
import argparse, hashlib, json, os, platform, sys, time
from pathlib import Path

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(); p.add_argument('--model',default='HuggingFaceTB/SmolLM2-135M-Instruct'); p.add_argument('--revision',required=True,help='Pin a full immutable model commit hash'); p.add_argument('--out',default='datasets/real_model_smoke.json'); p.add_argument('--prompt',default='Reply with the single word: READY'); a=p.parse_args()
    out={'schema_version':'1.0','experiment_id':'real-model-smoke-'+str(int(time.time())),'evidence_class':'observed','model_tested':False,'independent_trials':False,'model_id':a.model,'revision':a.revision,'timestamp_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'python':sys.version,'platform':platform.platform(),'prompt_sha256':hashlib.sha256(a.prompt.encode()).hexdigest(),'weights':[],'output':None,'status':'NOT_RUN'}
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        tok=AutoTokenizer.from_pretrained(a.model,revision=a.revision,trust_remote_code=False)
        model=AutoModelForCausalLM.from_pretrained(a.model,revision=a.revision,trust_remote_code=False,torch_dtype='auto',low_cpu_mem_usage=True)
        out['model_tested']=True; out['status']='PASS_SMOKE_ONLY'
        prompt=tok(a.prompt,return_tensors='pt'); start=time.time()
        with torch.inference_mode(): ids=model.generate(**prompt,max_new_tokens=24,do_sample=False)
        out['output']=tok.decode(ids[0],skip_special_tokens=True); out['elapsed_seconds']=time.time()-start
        for f in Path(getattr(model,'name_or_path',a.model)).glob('*.safetensors'): out['weights'].append({'path':str(f),'sha256':sha(f)})
        out['torch_version']=torch.__version__; out['transformers_version']=__import__('transformers').__version__
    except Exception as e:
        out['status']='NOT_RUN'; out['error_type']=type(e).__name__; out['error']=str(e); out['model_tested']=False
    Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'status':out['status'],'model_tested':out['model_tested'],'out':a.out},indent=2))
    return 0 if out['model_tested'] else 2
if __name__=='__main__': raise SystemExit(main())
