'use strict';
let books=[], book='', chart=[], banks=[], bank='', documentsOffset=0, transactionsOffset=0;
let statementPreview=null, xeroPreview=null, transactionId=null;
const formData=f=>Object.fromEntries(new FormData(f));
const freshId=()=>crypto.randomUUID();
const accounting=(action,data={},bookId=book)=>api('accounting',{action,book_id:bookId||null,data});
function clearAccounting(){if(typeof clearPostings==='function')clearPostings();books=[];book='';chart=[];banks=[];bank='';statementPreview=null;xeroPreview=null;transactionId=null;$('reconcile-dialog')?.close();$('feed-form')?.reset();}
function options(select,rows,current,label){select.replaceChildren(...rows.map(r=>{const o=el('option',label(r));o.value=r.id;return o;}));if(rows.some(r=>r.id===current)) select.value=current;}
function table(target,head,rows){const t=el('table'),h=el('thead'),hr=el('tr'),body=el('tbody');head.forEach(x=>hr.append(el('th',x)));h.append(hr);rows.forEach(row=>{const tr=el('tr');row.forEach(x=>{const td=el('td');if(x instanceof Node) td.append(x);else td.textContent=x??'—';tr.append(td);});body.append(tr);});t.append(h,body);$(target).replaceChildren(t);if(!rows.length)$(target).append(el('p','No records to show.','muted'));}
function showError(e){toast(e.message);text('global-error',e.message);$('global-error').hidden=false;}
function bindForm(id,fn){$(id).addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{if(!overview?.primary)throw new Error('Use the primary node for changes.');await fn(formData(e.target),e.target);revision++;await refresh();}catch(e){showError(e);}finally{b.disabled=false;}});}
function actionButton(label,fn){const b=el('button',label,'secondary');b.disabled=!overview?.primary;b.addEventListener('click',async()=>{b.disabled=true;try{await fn();revision++;await refresh();}catch(e){showError(e);}finally{b.disabled=!overview?.primary;}});return b;}
async function refreshAccounting(view,current){
 const b=await accounting('books',{},null);if(current!==revision)return;books=b;if(!books.some(b=>b.id===book))book=books[0]?.id||'';
 document.querySelectorAll('.book-select').forEach(s=>options(s,books,book,b=>b.name+' · '+b.currency));
 if(!book){table('trial-table',['Accounts'],[]);table('bank-table',['Accounts'],[]);return;}
 const c=await accounting('chart');if(current!==revision)return;chart=c;
 document.querySelectorAll('.contra-select').forEach(s=>options(s,chart.filter(c=>!c.control).map(c=>({...c,id:c.code})),s.value,c=>c.code+' · '+c.name));
 options($('bank-ledger'),chart.filter(c=>c.bank&&!c.control).map(c=>({...c,id:c.code})),$('bank-ledger').value,c=>c.code+' · '+c.name);
 if(view==='finance'){
  await refreshPostings(current);
  const tb=await accounting('trial-balance',{as_of:$('tb-date').value});if(current!==revision)return;
  text('tb-summary',tb.currency+' · Debits '+tb.debit+' · Credits '+tb.credit+' · '+(tb.balanced?'Balanced':'OUT OF BALANCE'));
  table('trial-table',['Code','Account','Type','Debit','Credit'],tb.rows.map(r=>[r.code,r.name,r.kind,r.debit,r.credit]));
  table('chart-table',['Code','Account','Type','Bank','Control'],chart.map(r=>[r.code,r.name,r.kind,r.bank?'Yes':'',r.control]));
  const d=await accounting('documents',{offset:documentsOffset});if(current!==revision)return;
  table('documents-table',['ID','Number','Type','Contact','Due','Total','Outstanding'],d.rows.map(r=>[r.id,r.number,r.kind,r.contact,r.due,r.total,r.outstanding]));text('docs-page','Rows '+(documentsOffset+1)+'–'+(documentsOffset+d.rows.length));$('docs-prev').disabled=!documentsOffset;$('docs-next').disabled=d.rows.length<200;
 }
 if(view==='banking'){
  const bs=await accounting('bank-accounts');if(current!==revision)return;banks=bs;if(!banks.some(b=>b.id===bank))bank=banks[0]?.id||'';
  document.querySelectorAll('.bank-select').forEach(s=>options(s,banks,s.id==='review-bank'?bank:s.value,b=>b.name+' · '+b.ledger_account));
  table('bank-table',['Account','Ledger','Import from','Feed balance','As of','Needs review'],banks.map(b=>[b.name,b.ledger_account,b.import_from,b.feed_balance,date(b.balance_at),b.unmatched]));
  const feeds=await accounting('feed-connections');if(current!==revision)return;$('feed-list').replaceChildren();
  for(const f of feeds){const row=el('div',undefined,'feed-row'),copy=el('div',undefined,'feed-copy');copy.append(el('strong',f.name),el('small',(f.active?'Connected':'Disconnected')+' · Last sync: '+(f.last_sync?new Date(f.last_sync).toLocaleString():'Never')+' · Next: '+new Date(f.next_sync).toLocaleString()));for(const err of f.errors||[])copy.append(el('p',typeof err==='string'?err:err.message,'form-error'));row.append(copy);if(f.active){row.append(actionButton('Sync',async()=>{const s=await accounting('feed-sync',{id:f.id});toast(s.complete?'Sync complete: '+s.new_transactions+' new transactions.':'Feed needs attention; review the connection messages.');}));row.append(actionButton('Disconnect',async()=>{await accounting('feed-disconnect',{id:f.id});toast('Polling stopped. Revoke the app in SimpleFIN too.');}));}$('feed-list').append(row);}
  if(!feeds.length)$('feed-list').append(el('p','No bank connections. Use SimpleFIN or import a statement.','muted'));
  const mappings=await accounting('feed-accounts');if(current!==revision)return;$('feed-mapping').replaceChildren();
  for(const a of mappings){const row=el('div',undefined,'feed-row');row.append(el('span',a.name+' · '+a.currency));if(a.bank_id)row.append(el('span','Mapped to '+a.bank_id,'badge neutral'));else{const select=el('select');select.setAttribute('aria-label','Map '+a.name);options(select,banks,'',b=>b.name);row.append(select,actionButton('Map account',async()=>{await accounting('feed-map',{connection_id:a.connection_id,source_key:a.source_key,bank_id:select.value});toast('Mapped. Transactions will arrive at the next permitted refresh.');}));}$('feed-mapping').append(row);}
  if(bank){const tx=await accounting('bank-transactions',{bank_id:bank,offset:transactionsOffset});if(current!==revision)return;
   table('transaction-table',['Date','Description','Amount','State','Review'],tx.rows.map(r=>{const description=el('div');description.append(el('strong',r.description));if(r.possible_duplicate)description.append(el('small','Possible duplicate · compare before posting','form-error'));if(r.note)description.append(el('small',r.note));const b=actionButton('Review',async()=>{transactionId=r.id;$('reconcile-form').reset();text('reconcile-description',r.date+' · '+r.amount+' · '+r.description);text('reconcile-error','');$('reconcile-dialog').showModal();});return[r.date,description,r.amount,r.state,b];}));text('tx-page','Rows '+(transactionsOffset+1)+'–'+(transactionsOffset+tx.rows.length));$('tx-prev').disabled=!transactionsOffset;$('tx-next').disabled=tx.rows.length<200;
  }else table('transaction-table',['Transactions'],[]);
 }
}
document.querySelectorAll('.book-select').forEach(s=>s.addEventListener('change',()=>{book=s.value;bank='';documentsOffset=0;transactionsOffset=0;statementPreview=null;xeroPreview=null;$('statement-preview').hidden=true;$('xero-preview').hidden=true;revision++;void refresh();}));
$('tb-date').value=new Date().toISOString().slice(0,10);$('tb-date').addEventListener('change',()=>void refresh());
$('review-bank').addEventListener('change',()=>{bank=$('review-bank').value;transactionsOffset=0;revision++;void refresh();});
for(const [id,delta,type]of [['docs-prev',-200,'docs'],['docs-next',200,'docs'],['tx-prev',-200,'tx'],['tx-next',200,'tx']])$(id).addEventListener('click',()=>{if(type==='docs')documentsOffset=Math.max(0,documentsOffset+delta);else transactionsOffset=Math.max(0,transactionsOffset+delta);revision++;void refresh();});
bindForm('book-form',async(d,f)=>{await accounting('create-book',{...d,scale:Number(d.scale)},null);book=d.id;f.reset();toast('Book created.');});
bindForm('ledger-account-form',async(d,f)=>{await accounting('add-account',{...d,bank:d.bank==='on',control:d.control||null,source_id:null});f.reset();toast('Ledger account added.');});
bindForm('contact-form',async(d,f)=>{await accounting('add-contact',{...d,source_id:null});f.reset();toast('Contact added.');});
bindForm('document-form',async(d,f)=>{f.dataset.requestId ||= freshId();const v=await accounting('create-document',{request_id:f.dataset.requestId,kind:d.kind,number:d.number,contact_id:d.contact_id,date:d.date,due:d.due,lines:[{account:d.account,amount:d.amount}]});delete f.dataset.requestId;f.reset();toast('Document posted: '+v.document_id);});
bindForm('bank-form',async(d,f)=>{await accounting('bank-create',d);bank=d.id;f.reset();toast('Bank account added.');});
bindForm('feed-form',async(d,f)=>{f.dataset.requestId ||= freshId();try{await accounting('feed-connect',{...d,id:f.dataset.requestId});delete f.dataset.requestId;f.reset();toast('Connected. Sync to discover accounts.');}finally{f.elements.setup_token.value='';}});
bindForm('statement-form',async(d)=>{if(d.file.size>2*1024*1024)throw new Error('Maximum statement size is 2 MiB.');const v=await accounting('bank-preview',{bank_id:d.bank_id,format:d.format,content:await d.file.text()});statementPreview={...v,book};text('statement-summary',v.count+' transactions · '+v.message+' '+v.warnings.join(' '));table('statement-table',['Date','Amount','Description'],v.preview.map(r=>[r.date,r.amount,r.description]));$('statement-preview').hidden=false;$('statement-commit').disabled=v.state==='committed';});
$('statement-commit').addEventListener('click',async()=>{const b=$('statement-commit');b.disabled=true;try{if(!statementPreview||statementPreview.book!==book)throw new Error('Preview the statement again.');const r=await accounting('bank-commit',{id:statementPreview.id,hash:statementPreview.hash});toast((r.new_transactions||0)+' transactions added to review.');$('statement-preview').hidden=true;await refresh();}catch(e){showError(e);b.disabled=false;}});
bindForm('xero-form',async(d)=>{if(d.file.size>3*1024*1024)throw new Error('Maximum bundle size is 3 MiB.');const v=await accounting('xero-preview',JSON.parse(await d.file.text()));xeroPreview={...v,book};$('xero-summary').replaceChildren(...Object.entries(v.summary).map(([k,v])=>el('p',k.replaceAll('_',' ')+': '+(Array.isArray(v)?v.join(' '):v))));$('xero-preview').hidden=false;$('xero-commit').disabled=v.state==='committed';});
$('xero-commit').addEventListener('click',async()=>{const b=$('xero-commit');b.disabled=true;try{if(!xeroPreview||xeroPreview.book!==book)throw new Error('Preview the cutover again.');await accounting('xero-commit',{id:xeroPreview.id,hash:xeroPreview.hash});toast('Opening balances posted. Cutover date locked.');$('xero-preview').hidden=true;await refresh();}catch(e){showError(e);b.disabled=false;}});
$('reconcile-cancel').addEventListener('click',()=>$('reconcile-dialog').close());
$('reconcile-form').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{const d=formData(e.target);await accounting(d.action,{...d,id:transactionId});$('reconcile-dialog').close();toast('Transaction review updated.');await refresh();}catch(e){text('reconcile-error',e.message);}finally{b.disabled=false;}});
