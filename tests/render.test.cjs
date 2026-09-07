const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {JSDOM}=require('jsdom');
test('telemetry, model fields and raw JSON remain text',()=>{
  const dom=new JSDOM(readFileSync('sentinel_dashboard.html','utf8'),{runScripts:'dangerously'});
  const w=dom.window, payload='<img data-pwn="yes" src=x onerror="window.pwned=true">';
  w.SD={system:{hostname:payload,username:payload,firewall:[{profile:payload}]},event_summary:{total:payload},event_logs:[{description:payload,id:payload,user:payload}],processes:[{name:payload,path:payload,is_lolbin:true}],network:{tcp_connections:[{process:payload,remote_address:payload,is_external:true}]},dns_cache:{entries:[{name:payload}]},persistence:{registry_run_keys:[{name:payload,value:payload}],scheduled_tasks:[{action:payload}],services:[{path:payload}]},filesystem:{recent_suspicious_files:[{path:payload}]},users:{local_users:[{name:payload}],local_admins:[{name:payload}],logged_on:[{username:payload}]}};
  w.AR={sum:{top_priorities:[payload]},ev:{label:payload,data:{findings:[{title:payload,description:payload,remediation:payload,severity:payload}]}}};
  w.renderDash([{cfg:{label:payload}}],true);
  assert.equal(w.document.querySelector('[data-pwn]'),null);
  assert.equal(w.pwned,undefined);
  for(const id of ['sprof','etbl','ltbl','extbl','rtbl','tktbl','stbl','fftbl','upnl','flist','ai-panels'])assert.ok(w.document.getElementById(id).textContent.includes(payload),id);
  assert.equal(w.document.querySelector('#flist .finding').className,'finding low');
  // Re-render clears old findings safely.
  w.SD={};w.AR={};w.renderDash([],false);
  assert.equal(w.document.getElementById('flist').textContent,'No significant findings');
  dom.window.close();
});
