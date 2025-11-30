
function setStatus(text, cls){const el=document.getElementById('statusBar');el.textContent=text;el.className=cls?cls:'idle';}

async function encryptAndDownload(){
  const msg = document.getElementById('enc-msg');
  const filenameRaw = document.getElementById('enc-filename').value.trim() || 'document.zsl';
  const filename = filenameRaw.endsWith('.zsl') ? filenameRaw : filenameRaw + '.zsl';
  const pass = document.getElementById('enc-pass').value;
  const content = document.getElementById('enc-content').value;
  msg.textContent=''; setStatus('Encrypting...', 'working');

  try{
    const res = await fetch('/api/encrypt-text', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ filename, passphrase: pass, content })
    });
    if(!res.ok){
      const text = await res.text();
      setStatus('Error', 'error');
      msg.textContent = 'Error: ' + text.slice(0,120);
      return;
    }
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setStatus('Idle', 'idle');
    msg.textContent='⬇️ Encrypted file downloaded.';
  }catch(e){
    setStatus('Error', 'error'); msg.textContent='Error: '+e.message;
  }
}

async function decryptFile(){
  const msg = document.getElementById('dec-msg');
  const fileInput = document.getElementById('dec-file');
  const pass = document.getElementById('dec-pass').value;
  const out = document.getElementById('dec-content');
  const btnDl = document.getElementById('btn-download-txt');
  msg.textContent=''; out.value=''; btnDl.disabled=true; setStatus('Decrypting...', 'working');

  if(!fileInput.files.length){ setStatus('Error', 'error'); msg.textContent='Choose a .zsl file first.'; return; }

  const fd = new FormData();
  fd.append('file', fileInput.files[0]);
  fd.append('passphrase', pass);

  try{
    const res = await fetch('/api/decrypt-file', { method:'POST', body: fd });
    const text = await res.text();
    let data;
    try{ data = JSON.parse(text); }catch{ setStatus('Error', 'error'); msg.textContent = 'Server error: ' + text.slice(0,120); return; }
    if(!res.ok || !data.ok){ setStatus('Error', 'error'); msg.textContent = 'Error: ' + (data.error || 'Failed'); return; }
    out.value = data.text;
    btnDl.disabled=false;
    btnDl.onclick = () => {
      const file = document.getElementById('dec-file').files[0];
      let name = file ? file.name.replace(/\.zsl$/i,'.txt') : 'decrypted.txt';
      const blob = new Blob([out.value], {type:'text/plain;charset=utf-8'});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
    };
    setStatus('Idle', 'idle');
    msg.textContent='✅ Decrypted.';
  }catch(e){
    setStatus('Error', 'error'); msg.textContent='Error: '+e.message;
  }
}

function wirePassToggles(){
  document.querySelectorAll('.toggle-pass').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = document.getElementById(btn.dataset.target);
      target.type = target.type === 'password' ? 'text' : 'password';
    });
  });
}

function wireDragDrop(){
  const decCard = document.getElementById('decryptCard');
  if(!decCard) return;
  ['dragenter','dragover'].forEach(ev => decCard.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); decCard.classList.add('drag'); }));
  ;['dragleave','drop'].forEach(ev => decCard.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); decCard.classList.remove('drag'); }));
  decCard.addEventListener('drop', e => {
    const dt = e.dataTransfer;
    if(dt && dt.files && dt.files.length){
      const file = dt.files[0];
      if(file.name.toLowerCase().endsWith('.zsl')){
        document.getElementById('dec-file').files = dt.files;
        setStatus('Dropped file: ' + file.name, 'working');
        setTimeout(()=>setStatus('Idle','idle'), 800);
      }
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-encrypt').addEventListener('click', encryptAndDownload);
  document.getElementById('btn-decrypt').addEventListener('click', decryptFile);
  wirePassToggles();
  wireDragDrop();
});
