import { useEffect, useState } from 'react';
import { onlineRequest } from '../app/OnlineSession';
import { useAssessmentList } from '../app/context';
import { errorMessage } from '../api/client';
type Item={owner:string;dueDate:string;notes:string;exceptionExpiry:string;status:string;verificationAssessmentId:string};
const blank:Item={owner:'',dueDate:'',notes:'',exceptionExpiry:'',status:'open',verificationAssessmentId:''};
export function RemediationPanel({controlId}:{controlId:string}){
 const [item,setItem]=useState<Item>(blank);const [message,setMessage]=useState('');const [ready,setReady]=useState(false);const [saving,setSaving]=useState(false);const history=useAssessmentList();
 useEffect(()=>{const c=new AbortController();void onlineRequest(`/api/remediation/${encodeURIComponent(controlId)}`,c.signal).then(r=>{if(c.signal.aborted)return;setItem((r as {item:Item|null}).item??blank);setReady(true);}).catch(e=>{if(!c.signal.aborted)setMessage(errorMessage(e));});return ()=>c.abort();},[controlId]);
 const field=(key:keyof Item,value:string)=>setItem(old=>({...old,[key]:value}));
 const save=async()=>{setSaving(true);setMessage('');try{const {owner,dueDate,notes,exceptionExpiry,status,verificationAssessmentId}=item;await onlineRequest(`/api/remediation/${encodeURIComponent(controlId)}`,undefined,'POST',{owner,dueDate,notes,exceptionExpiry,status,verificationAssessmentId});setMessage('Tracking saved. Assessment verdicts are unchanged.');}catch(e){setMessage(errorMessage(e));}finally{setSaving(false);}};
 return <details className="remediation-panel"><summary>Track remediation and exceptions</summary><p className="muted small">Shared with authorised administrators in this tenant. Exceptions do not change the assessment verdict. Do not enter credentials or confidential message content.</p><div className="tracking-fields">
 <label>Owner<input className="input" maxLength={200} value={item.owner} onChange={e=>field('owner',e.target.value)}/></label>
 <label>Due date<input className="input" type="date" value={item.dueDate} onChange={e=>field('dueDate',e.target.value)}/></label>
 <label>Tracking status<select className="select" value={item.status} onChange={e=>field('status',e.target.value)}><option value="open">Open</option><option value="in-progress">In progress</option><option value="exception">Documented exception</option><option value="resolved">Verified resolved</option></select></label>
 <label>Exception expiry<input className="input" type="date" value={item.exceptionExpiry} onChange={e=>field('exceptionExpiry',e.target.value)}/></label>
 <label className="tracking-notes">Notes / exception reason<textarea className="input" maxLength={2000} value={item.notes} onChange={e=>field('notes',e.target.value)}/></label>
 {item.status==='resolved'?<label>Verification assessment<select className="select" value={item.verificationAssessmentId} onChange={e=>field('verificationAssessmentId',e.target.value)}><option value="">Select latest passing assessment</option>{history.status==='success'?history.data.map(a=><option key={a.assessmentId} value={a.assessmentId}>{a.assessedAt}</option>):null}</select></label>:null}</div>
 {item.status==='exception'&&item.exceptionExpiry<new Date().toISOString().slice(0,10)?<p className="error-text">This exception has expired and needs review.</p>:null}
 <button className="button button--primary" disabled={!ready||saving} onClick={()=>void save()}>{saving?'Saving…':'Save tracking'}</button><p role="status">{message}</p></details>;
}
