function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]
  );
}

function safeUrl(url) {
  return /^(https?:|mailto:|\/|#|\.)/i.test(url) ? url : null;
}

function inline(text) {
  let s = text;
  s = s.replace(/`([^`]+)`/g, (_, code) => `<code>${code}</code>`);
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>');
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (whole, label, url) => {
    const safe = safeUrl(url);
    return safe
      ? `<a href="${safe}" target="_blank" rel="noopener noreferrer">${label}</a>`
      : whole;
  });
  return s;
}

export function renderMarkdown(source) {
  const lines = escapeHtml(source || '').split('\n');
  let out = '';
  let inCode = false;
  let list = null;
  let para = [];
  const flushPara = () => {
    if (para.length) {
      out += `<p>${para.join('<br>')}</p>`;
      para = [];
    }
  };
  const closeList = () => {
    if (list) {
      out += `</${list}>`;
      list = null;
    }
  };
  for (const line of lines) {
    if (line.trim().startsWith('```')) {
      flushPara();
      closeList();
      out += inCode ? '</code></pre>' : '<pre><code>';
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      out += `${line}\n`;
      continue;
    }
    if (/^\s*$/.test(line)) {
      flushPara();
      closeList();
      continue;
    }
    let m = line.match(/^(#{1,6})\s+(.*)$/);
    if (m) {
      flushPara();
      closeList();
      out += `<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`;
      continue;
    }
    if (/^\s*([-*_])\1{2,}\s*$/.test(line)) {
      flushPara();
      closeList();
      out += '<hr>';
      continue;
    }
    m = line.match(/^&gt;\s?(.*)$/);
    if (m) {
      flushPara();
      closeList();
      out += `<blockquote>${inline(m[1])}</blockquote>`;
      continue;
    }
    m = line.match(/^\s*[-*+]\s+(.*)$/);
    if (m) {
      flushPara();
      if (list !== 'ul') {
        closeList();
        out += '<ul>';
        list = 'ul';
      }
      out += `<li>${inline(m[1])}</li>`;
      continue;
    }
    m = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (m) {
      flushPara();
      if (list !== 'ol') {
        closeList();
        out += '<ol>';
        list = 'ol';
      }
      out += `<li>${inline(m[1])}</li>`;
      continue;
    }
    closeList();
    para.push(inline(line));
  }
  flushPara();
  closeList();
  if (inCode) out += '</code></pre>';
  return out;
}
