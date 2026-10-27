/* Native upload byte progress; server processing has elapsed time, not a fake %. */
(() => {
  'use strict';
  const get = id => document.getElementById(id);
  let timer = null;
  let processingStarted = null;
  let uploadComplete = false;
  let requestActive = false;
  function stopTimer() {
    if (timer !== null) window.clearInterval(timer);
    timer = null;
  }
  function reset() {
    if (requestActive) return;
    stopTimer();
    processingStarted = null;
    uploadComplete = false;
    get('upload-status').hidden = true;
    get('upload-status').dataset.state = 'idle';
    get('server-elapsed').hidden = true;
    get('upload-progress').value = 0;
    get('upload-percent').textContent = '0%';
    get('upload-phase').textContent = '업로드 대기';
    get('upload-bytes').textContent = '';
  }
  function elapsed() {
    if (processingStarted === null) return;
    const seconds = Math.floor((performance.now() - processingStarted) / 1000);
    get('server-elapsed').textContent = '서버 처리 대기: ' + seconds + '초 · 준비·대기열·분석·결과 수신 포함';
  }
  const size = bytes => (bytes / 1024 / 1024).toFixed(1) + ' MiB';
  function send(file, onUploaded) {
    if (requestActive) return Promise.reject(new Error('이미 파일을 전송하고 있습니다.'));
    reset();
    requestActive = true;
    const panel = get('upload-status');
    panel.hidden = false;
    panel.dataset.state = 'uploading';
    get('upload-phase').textContent = '파일 업로드 중';
    get('upload-bytes').textContent = '전송을 시작합니다.';
    return new Promise((resolve, reject) => {
      let xhr;
      let settled = false;
      function finish(error, output) {
        if (settled) return;
        settled = true;
        elapsed();
        requestActive = false;
        if (error) {
          stopTimer();
          panel.dataset.state = 'error';
          get('upload-phase').textContent = uploadComplete ? '업로드 완료 · 접수 오류' : '업로드 중단';
        } else {
          panel.dataset.state = 'processing';
          get('upload-phase').textContent = '업로드 완료 · 작업 접수';
        }
        if (error) reject(error); else resolve(output);
      }
      function uploaded() {
        if (settled || uploadComplete) return;
        uploadComplete = true;
        get('upload-progress').value = 100;
        get('upload-percent').textContent = '100%';
        get('upload-phase').textContent = '업로드 완료 · 서버 처리 중';
        get('upload-bytes').textContent = size(file.size) + ' 파일 전송 완료';
        get('server-elapsed').hidden = false;
        processingStarted = performance.now();
        elapsed();
        timer = window.setInterval(elapsed, 1000);
        if (typeof onUploaded === 'function') onUploaded();
      }
      try {
        xhr = new XMLHttpRequest();
      } catch (error) {
        finish(error);
        return;
      }
      xhr.upload.addEventListener('progress', event => {
        if (settled || uploadComplete) return;
        if (event.lengthComputable && event.total > 0) {
          const percent = Math.min(100, Math.max(0, Math.floor(event.loaded / event.total * 100)));
          get('upload-progress').value = percent;
          get('upload-percent').textContent = percent + '%';
          get('upload-bytes').textContent = size(event.loaded) + ' / ' + size(event.total) + ' 전송';
        } else {
          get('upload-progress').removeAttribute('value');
          get('upload-percent').textContent = '전송 중';
          get('upload-bytes').textContent = size(event.loaded) + ' 전송 · 전체 크기 확인 중';
        }
      });
      xhr.upload.addEventListener('load', uploaded);
      xhr.addEventListener('load', () => {
        const output = xhr.response;
        if (xhr.status < 200 || xhr.status >= 300) {
          const message = output && typeof output.detail === 'string'
            ? output.detail : '분석에 실패했습니다. 서버 상태를 확인해 주세요.';
          finish(new Error(message));
          return;
        }
        if (!output || typeof output !== 'object') {
          finish(new Error('서버 응답을 읽을 수 없습니다.'));
          return;
        }
        if (typeof output.job_id !== 'string' || !/^[0-9a-f]{32}$/.test(output.job_id) || typeof output.status !== 'string') {
          finish(new Error('작업 접수 응답 형식이 올바르지 않습니다.'));
          return;
        }
        // A successful scan response proves upload completion even if the
        // browser coalesced all progress events for a fast local transfer.
        uploaded();
        finish(null, output);
      });
      xhr.addEventListener('error', () => finish(new Error('서버에 연결할 수 없습니다. 서버 실행 상태를 확인해 주세요.')));
      xhr.addEventListener('abort', () => finish(new Error('파일 전송 요청이 중단됐습니다.')));
      xhr.addEventListener('timeout', () => finish(new Error('서버 응답 대기 시간이 초과됐습니다.')));
      try {
        xhr.open('POST', '/scan');
        xhr.responseType = 'json';
        // Server analysis timeout is separate from potentially slow upload time.
        xhr.timeout = 0;
        const data = new FormData();
        data.append('file', file);
        xhr.send(data);
      } catch (error) {
        finish(error);
      }
    });
  }
  function jobStatus(label, terminal=false, error=false) {
    get('upload-phase').textContent = label;
    get('upload-status').dataset.state = terminal ? (error ? 'error' : 'complete') : 'processing';
    if (terminal) { elapsed(); stopTimer(); }
  }
  window.envyUpload = {send, reset, jobStatus};
})();
