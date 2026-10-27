(() => {
  'use strict';
  const el=id=>document.getElementById(id);
  let selected=null,busy=false,maxSize=0,label='',pollLimit=2200;
  const stages={uploading:'파일 준비 중',queued:'대기열에서 순서를 기다리는 중',running:'분석 중',
    cache_lookup:'기존 분석 결과 확인',read_file:'파일 읽기',pe_validation:'PE 형식 확인',
    metadata:'파일 상세정보 추출',feature_extraction:'모델 특징 추출',inference:'모델 예측',
    cache_hit:'기존 분석 결과 사용',completed:'분석 완료',failed:'분석 실패'};
  function result(kind,title,message,badge){
    window.envyDetails?.reset();
    el('result-panel').className='panel result-panel '+kind;
    el('badge').textContent=badge;el('verdict').textContent=title;el('description').textContent=message;
    el('metrics').hidden=true;const icon=el('status-icon');icon.replaceChildren();
    if(kind==='loading'){const x=document.createElement('span');x.className='spinner';icon.append(x);}
    else icon.textContent=kind==='safe'?'✓':kind==='danger'?'!':kind==='error'?'!':'⌕';
  }
  function setBusy(value){
    busy=value;el('file').disabled=value||!maxSize;el('submit').disabled=value||!selected||!maxSize;
    el('button-spinner').hidden=!value;el('arrow').hidden=value;
    el('button-label').textContent=value?'검사 진행 중…':'파일 검사하기';
    el('drop').classList.toggle('busy',value);el('result-panel').setAttribute('aria-busy',String(value));
  }
  function select(file){
    if(busy||!maxSize)return;
    window.envyUpload.reset();selected=null;el('submit').disabled=true;
    if(!file){el('file-meta').textContent='선택한 파일이 없습니다.';result('','검사할 파일을 선택하세요','파일 하나를 선택해 주세요.','대기 중');return;}
    el('file-meta').textContent=file.name+' · '+(file.size/1024/1024).toFixed(2)+' MiB';
    let error='';
    if(!/\.(exe|dll)$/i.test(file.name))error='.exe 또는 .dll 파일을 선택해 주세요.';
    else if(!file.size)error='빈 파일은 분석할 수 없습니다.';
    else if(file.size>maxSize)error=label+' 이하의 파일을 선택해 주세요.';
    if(error){el('file').value='';result('error','파일을 확인해 주세요',error,'선택 오류');return;}
    selected=file;el('submit').disabled=false;
    result('','검사 준비가 됐습니다','버튼을 누르면 파일을 전송하고 작업을 접수합니다.','준비 완료');
  }
  async function json(url,options){
    const response=await fetch(url,options);let value;
    try{value=await response.json();}catch{throw new Error('서버 응답을 읽지 못했습니다.');}
    if(!response.ok)throw new Error(typeof value.detail==='string'?value.detail:'서버 요청에 실패했습니다.');
    return value;
  }
  function show(job){
    const data=job.result;
    if(!data||typeof data.score!=='number'||!Number.isFinite(data.score)||data.score<0||data.score>1||typeof data.verdict!=='string')throw new Error('분석 결과 형식이 올바르지 않습니다.');
    const cached=job.result_source==='cache';
    result(data.score>=.5?'danger':'safe',data.verdict,job.filename||data.filename||'',cached?'캐시 결과':'분석 완료');
    el('score').textContent=data.score.toFixed(6);el('fill').style.width=(data.score*100)+'%';el('metrics').hidden=false;
    window.envyDetails?.render(data);
    window.envyUpload.jobStatus(cached?'업로드 완료 · 기존 분석 결과 사용':'업로드 완료 · 검사 완료',true);
  }
  const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
  async function follow(initial){
    let job=initial, failures=0;
    const started=performance.now();
    while(true){
      if(job.status==='succeeded'){show(job);return;}
      if(job.status==='failed')throw new Error(job.error||'분석에 실패했습니다.');
      const stage=stages[job.stage]||stages[job.status]||'서버 처리 중';
      const queued=job.status==='queued'||job.status==='uploading';
      result('loading',queued?'분석 대기 중':'파일을 분석하고 있습니다',stage,queued?'대기 중':'분석 중');
      window.envyUpload.jobStatus('업로드 완료 · '+stage);
      if((performance.now()-started)/1000>pollLimit)throw new Error('상태 확인 시간이 길어졌습니다. 검사 기록에서 작업 결과를 다시 확인해 주세요.');
      await sleep(1000);
      try{job=await json('/jobs/'+initial.job_id,{cache:'no-store'});failures=0;}
      catch(error){if(++failures>=3)throw new Error(error.message+' 검사 기록에서 다시 확인할 수 있습니다.');}
    }
  }
  el('file').addEventListener('change',()=>select(el('file').files[0]));
  for(const name of ['dragenter','dragover'])el('drop').addEventListener(name,event=>{event.preventDefault();if(!busy)el('drop').classList.add('drag');});
  el('drop').addEventListener('dragleave',event=>{if(!el('drop').contains(event.relatedTarget))el('drop').classList.remove('drag');});
  el('drop').addEventListener('drop',event=>{
    event.preventDefault();el('drop').classList.remove('drag');if(busy||!maxSize)return;
    window.envyUpload.reset();el('file').value='';
    if(event.dataTransfer.files.length!==1){selected=null;el('submit').disabled=true;el('file-meta').textContent='선택한 파일이 없습니다.';result('error','파일을 하나만 선택해 주세요','한 번에 하나씩 검사할 수 있습니다.','선택 오류');return;}
    select(event.dataTransfer.files[0]);
  });
  window.addEventListener('dragover',event=>event.preventDefault());window.addEventListener('drop',event=>event.preventDefault());
  el('scan-form').addEventListener('submit',async event=>{
    event.preventDefault();if(busy||!selected)return;setBusy(true);
    result('loading','파일을 업로드하고 있습니다','왼쪽에서 실제 전송 진행률을 확인하세요.','업로드 중');
    try{
      const job=await window.envyUpload.send(selected,()=>result('loading','업로드 완료 · 작업 접수 중','기존 결과 확인 또는 작업 등록을 기다리고 있습니다.','접수 중'));
      await follow(job);
    }catch(error){result('error','분석하지 못했습니다',error.message,'분석 오류');window.envyUpload.jobStatus('서버 처리 오류',true,true);}
    finally{setBusy(false);await history();}
  });
  async function history(){
    try{
      const data=await json('/history',{cache:'no-store'});el('history-body').replaceChildren();
      for(const job of data.items||[]){
        const row=document.createElement('tr');
        const time=new Date(job.created_at).toLocaleString('ko-KR');
        const values=[time,job.filename,{queued:'대기 중',uploading:'준비 중',running:'분석 중',succeeded:'완료',failed:'실패'}[job.status]||job.status,
          typeof job.score==='number'?job.score.toFixed(6):'—',job.result_source==='cache'?'캐시':'새 분석'];
        for(let i=0;i<values.length;i++){
          const cell=document.createElement('td');
          if(i===1&&job.status==='succeeded'){
            const button=document.createElement('button');button.className='history-open';button.type='button';button.textContent=values[i];
            button.addEventListener('click',async()=>{if(busy)return;try{const record=await json('/jobs/'+job.id);window.envyUpload.reset();show(record);}catch(error){result('error','기록을 읽지 못했습니다',error.message,'조회 오류');}});
            cell.append(button);
          }else cell.textContent=values[i];
          row.append(cell);
        }
        el('history-body').append(row);
      }
      el('history-note').textContent=(data.items||[]).length?'최근 20개 작업입니다. 완료된 파일명을 누르면 결과를 확인할 수 있습니다.':'아직 검사 기록이 없습니다.';
    }catch{el('history-note').textContent='검사 기록을 불러오지 못했습니다.';}
  }
  el('refresh-history').addEventListener('click',history);
  (async()=>{
    try{
      const config=await json('/config',{cache:'no-store'});
      if(!Number.isSafeInteger(config.max_file_size_bytes)||config.max_file_size_bytes<=0)throw new Error('잘못된 설정입니다.');
      maxSize=config.max_file_size_bytes;label=config.max_file_size_label;
      el('size-limit').textContent='최대 '+label;el('file').disabled=false;await history();
    }catch(error){el('size-limit').textContent='설정 확인 필요';result('error','서버 설정을 읽지 못했습니다',error.message,'연결 오류');}
  })();
})();
