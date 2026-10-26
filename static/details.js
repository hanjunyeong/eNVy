/* PE 메타데이터 표시. 파일에서 읽은 문자열은 HTML로 해석하지 않습니다. */
(() => {
  'use strict';
  const panel = document.getElementById('detail-panel');
  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }
  function reset() {
    panel.hidden = true;
    panel.replaceChildren();
  }
  function render(output) {
    reset();
    panel.hidden = false;
    const heading = element('div', undefined, 'details-heading');
    const title = element('h2', '파일 상세 분석');
    title.id = 'detail-title';
    heading.append(title, element('span', 'PE STRUCTURE'));
    panel.append(heading);
    const info = output.details;
    if (!info) {
      panel.append(element('p', output.details_error || '상세정보를 받지 못했습니다. app.py와 pe_details.py가 모두 적용됐는지 확인해 주세요.', 'details-note'));
      return;
    }
    panel.append(element('p', '파일에서 읽은 구조 정보입니다. 모델이 왜 이런 점수를 냈는지에 대한 설명이나 실제 실행 동작을 뜻하지 않습니다.', 'details-note'));
    const summary = element('dl', undefined, 'details-summary');
    function field(label, value, wide=false, hash=false) {
      const box = element('div', undefined, wide ? 'wide' : undefined);
      box.append(element('dt', label), element('dd', value ?? '확인 불가', hash ? 'hash' : undefined));
      summary.append(box);
    }
    field('SHA-256', info.sha256, true, true);
    field('파일 크기', typeof info.size_bytes === 'number' ? info.size_bytes.toLocaleString('ko-KR') + ' bytes' : null);
    field('PE 형식', info.pe_format);
    field('대상 아키텍처', info.machine);
    field('파일 종류', info.kind);
    field('진입점 (RVA)', info.entry_point);
    field('섹션 수', info.section_count);
    panel.append(summary);

    panel.append(element('h3', '섹션 구조'));
    const scroll = element('div', undefined, 'table-scroll');
    scroll.tabIndex = 0;
    scroll.setAttribute('role', 'region');
    scroll.setAttribute('aria-label', 'PE 섹션 표, 좁은 화면에서는 가로로 스크롤할 수 있습니다.');
    const table = element('table', undefined, 'section-table');
    const thead = element('thead');
    const header = element('tr');
    for (const name of ['섹션', '가상 크기 (B)', '파일 내 크기 (B)', '엔트로피', '메모리 권한']) {
      const th = element('th', name); th.scope = 'col'; header.append(th);
    }
    thead.append(header);
    const body = element('tbody');
    for (const section of info.sections || []) {
      const row = element('tr');
      row.append(element('td', section.name), element('td', section.virtual_size), element('td', section.raw_size));
      const entropy = element('td', undefined, 'entropy-cell');
      const value = section.entropy;
      if (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 8) {
        entropy.append(element('span', value.toFixed(3), 'entropy-value'));
        const bar = element('span', undefined, 'entropy-bar'); bar.setAttribute('aria-hidden', 'true');
        const fill = element('span'); fill.style.width = (value / 8 * 100) + '%';
        bar.append(fill); entropy.append(bar);
      } else entropy.textContent = '확인 불가';
      row.append(entropy, element('td', section.permissions)); body.append(row);
    }
    table.append(thead, body); scroll.append(table); panel.append(scroll);
    panel.append(element('p', '엔트로피는 바이트 분포의 불규칙성을 0~8로 나타냅니다. 압축된 정상 파일에서도 높을 수 있으며, 이 값만으로 악성을 판정하지 않습니다. R 읽기 · W 쓰기 · X 실행 권한.', 'detail-hint'));
    if (info.sections_truncated) panel.append(element('p', '섹션이 많아 일부만 표시합니다.', 'detail-hint'));

    panel.append(element('h3', '가져오는 DLL · 함수'));
    const states = {
      parsed: '일반 임포트 테이블을 읽었습니다. 아래 항목을 펼쳐 함수 목록을 확인하세요.',
      none: '일반 임포트 항목을 읽지 못했거나 항목이 없습니다. 항목이 없다는 사실이 안전함을 뜻하지 않습니다.',
      partial: '일반 임포트 정보를 일부만 읽었습니다. 표시 제한 또는 파서 경고를 확인하세요.',
      failed: '일반 임포트 테이블을 해석하지 못했습니다. 빈 목록을 안전하다는 의미로 해석하면 안 됩니다.'
    };
    panel.append(element('p', states[info.imports_status] || '임포트 상태를 확인하지 못했습니다.', 'import-state'));
    const imports = element('div', undefined, 'imports-list');
    for (const group of info.imports || []) {
      const item = element('details', undefined, 'import-item');
      const summary = element('summary', group.dll);
      summary.append(element('span', group.function_count + '개 함수' + (group.functions_truncated ? ' · 일부 표시' : ''), 'import-count'));
      const functions = element('div', undefined, 'function-list');
      for (const name of group.functions || []) functions.append(element('code', name));
      if (!(group.functions || []).length) functions.append(element('span', '표시할 함수 없음', 'detail-hint'));
      item.append(summary, functions); imports.append(item);
    }
    panel.append(imports);
    if (info.imports_truncated) panel.append(element('p', 'DLL 항목이 많아 일부만 표시합니다.', 'detail-hint'));
    panel.append(element('p', '일반 임포트 테이블 기준이며 지연 로드·실행 중 동적으로 불러오는 함수는 포함하지 않습니다. 목록에 있다는 사실만으로 해당 함수가 실제 실행됐다고 판단할 수 없습니다.', 'detail-hint'));
    if ((info.warnings || []).length || info.warnings_truncated) {
      const box = element('div', undefined, 'metadata-warnings');
      box.append(element('strong', '파서 경고 · 표시 제한'));
      const list = element('ul');
      for (const warning of info.warnings || []) list.append(element('li', warning));
      if (info.warnings_truncated) list.append(element('li', '추가 경고는 표시 제한으로 생략했습니다.'));
      box.append(list); panel.append(box);
    }
  }
  window.envyDetails = {reset, render};
})();
