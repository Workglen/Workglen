#!/usr/bin/env python3
"""Synthetic MIME inputs; standard library only, no network or real messages."""
import base64, json, sys
from email.message import EmailMessage
from email.policy import SMTP

def emit(label,raw,profile='exact'):
    if isinstance(raw,str):raw=raw.encode()
    print(json.dumps({'label':label,'profile':profile,'hex':raw.hex()},ensure_ascii=False))

def part(headers,body):return headers.encode()+b'\r\n\r\n'+(body.encode() if isinstance(body,str) else body)
def multi(subtype,parts,extra=''):
    return part('MIME-Version: 1.0\r\nContent-Type: multipart/'+subtype+'; boundary="b"'+extra,b'preamble\r\n'+b''.join(b'--b\r\n'+p+b'\r\n' for p in parts)+b'--b--\r\nepilogue')
emit('plain-crlf','From: Alice <a@example.test>\r\nTo: Bob <b@example.test>\r\nSubject: Hello\r\nMessage-ID: <m@example.test>\r\nDate: Sat, 25 Oct 2024 14:30:25 -0430\r\n\r\nHello\r\n')
emit('plain-lf','Subject: A\n\nHello\n')
emit('header-fold-and-repeat','Subject: First\r\nSubject: Second\r\nX-Custom: hello\r\n\tworld\r\n\r\ntext')
for name,value in [('group','Friends: Alice <a@example.test>, Bob <b@example.test>;'),('quoted','"Doe, Jane" <j@example.test>'),('comment','j@example.test (Jane (J) Doe)'),('route','Jane <@a.test,@b.test:j@example.test>'),('quoted-local','"a,b"@example.test'),('encoded','=?UTF-8?Q?Jos=C3=A9?= <j@example.test>'),('injected','=?UTF-8?Q?fake=3Cattacker=40test=3E?= <real@example.test>'),('literal','User <a@[IPv6:2001:db8::1]>')]:
 emit('address-'+name,'From: '+value+'\r\nTo: other@example.test\r\n\r\nHello')
for n,subject in enumerate(['=?UTF-8?Q?Hello_=E2=9C=93?=','=?ISO-8859-1?Q?caf=E9?=','=?UTF-8?B?8J+YgA==?=','=?UTF-8?Q?hello?=  \r\n\t=?UTF-8?Q?_world?=','prefix =?UTF-8?Q?encoded?= suffix']):emit('word-'+str(n),'Subject: '+subject+'\r\n\r\nx')
plain=part('Content-Type: text/plain; charset=utf-8','plain body')
html=part('Content-Type: text/html; charset=utf-8','<p>Hello <b>world</b> &amp; all</p>')
attach=part('Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\nContent-Transfer-Encoding: base64',base64.b64encode(bytes(range(16))))
image=part('Content-Type: image/png\r\nContent-ID: <image>\r\nContent-Disposition: inline\r\nContent-Transfer-Encoding: base64',base64.b64encode(b'PNG'))
emit('multipart-mixed',multi('mixed',[plain,attach]))
emit('multipart-alternative',multi('alternative',[plain,html]))
emit('multipart-related',multi('related',[html,image]))
emit('multipart-related-start',multi('related',[image,part('Content-Type: text/html\r\nContent-ID: <root>','<p>root</p>')],'; start="<root>"'), 'semantics')
emit('nested-multipart',multi('mixed',[multi('alternative',[plain,html]).replace(b'boundary="b"',b'boundary="inner"').replace(b'--b',b'--inner'),attach]))
for enc in ['7bit','base64']:
 nested=b'From: n@example.test\r\nSubject: nested\r\n\r\ninside\r\n'
 emit('message-'+enc,multi('mixed',[plain,part('Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename="forward.eml"\r\nContent-Transfer-Encoding: '+enc,base64.b64encode(nested) if enc=='base64' else nested)]))
emit('digest',multi('digest',[b'\r\nFrom: a@example.test\r\n\r\nmessage']))
for name,value in [('quoted','attachment; filename="a;b\\\"c.txt"'),('extended',"attachment; filename=old.txt; filename*=utf-8''caf%C3%A9.txt"),('continued',"attachment; filename*0*=utf-8'en'long%20; filename*1*=file%20; filename*2=name.txt"),('encoded-word','attachment; filename="=?UTF-8?Q?caf=C3=A9.txt?="')]:
 emit('filename-'+name,multi('mixed',[plain,part('Content-Type: application/octet-stream\r\nContent-Disposition: '+value,b'file')]))
for value in ['<p>A</p><p>B</p>','Hello<br>world','<style>bad</style><script>bad</script><p>good</p>','<p>&NotEqualTilde; &#x1F600; &copy; &nbsp;</p>','<a href="https://example.test">link</a>','<div> A  B\n C </div>']:
 emit('html-'+str(len(value))+'-'+value[:10],part('Content-Type: text/html',value),'projection')
for cs in ['utf-8','us-ascii','iso-8859-1','windows-1252','iso-8859-2','iso-8859-3','iso-8859-4','iso-8859-5','iso-8859-6','iso-8859-7','iso-8859-8','iso-8859-9','iso-8859-10','iso-8859-11','iso-8859-13','iso-8859-14','iso-8859-15','iso-8859-16','cp850','ibm866','windows-1250','windows-1251','windows-1253','windows-1254','windows-1255','windows-1256','windows-1257','windows-1258','koi8-r','koi8-u','macintosh','x-mac-cyrillic','tis-620']:
 emit('charset-bytes-'+cs,part('Content-Type: text/plain; charset='+cs+'\r\nContent-Transfer-Encoding: base64',base64.b64encode(bytes(range(256)))),'charset')
for cs,pycs,text in [('utf-7','utf-7','Hello + 世界'),('utf-16','utf-16','Hello 世界'),('utf-16be','utf-16be','Hello 世界'),('utf-16le','utf-16le','Hello 世界'),('shift_jis','shift_jis','日本語'),('iso-2022-jp','iso-2022-jp','日本語'),('euc-jp','euc_jp','日本語'),('gbk','gbk','中文'),('gb18030','gb18030','中文😀'),('big5','big5','中文'),('euc-kr','euc_kr','한국어')]:
 emit('charset-text-'+cs,part('Content-Type: text/plain; charset='+cs+'\r\nContent-Transfer-Encoding: base64',base64.b64encode(text.encode(pycs))))
for label,headers,body in [('qp','Content-Transfer-Encoding: quoted-printable','Hello=20world=0D=0Asoft=\r\nline'),('boundary-prefix','Content-Type: multipart/mixed; boundary=b',b'--bX\r\nno match\r\n--b\r\n\r\nHello\r\n--b--\r\n')]:emit(label,part(headers,body))
# Independent Python-standard-library writer covers its normal MIME arrangement.
for n in range(12):
 m=EmailMessage(policy=SMTP);m['From']='Alice <a@example.test>';m['To']='Bob <b@example.test>';m['Subject']='Fixture café '+str(n);m.set_content('Hello café\n',cte=['7bit','quoted-printable','base64'][n%3] if n%3 else '8bit')
 if n%2:m.add_alternative('<p>Hello café</p>',subtype='html')
 if n%3:m.add_attachment(bytes(range(n+1)),maintype='application',subtype='octet-stream',filename='café.bin')
 for i,p in enumerate(m.walk()):
  if p.is_multipart():p.set_boundary('fixture-'+str(n)+'-'+str(i))
 emit('stdlib-'+str(n),m.as_bytes())

# All charset labels accepted by the previous public decoder API. Empty content
# tests recognition without mixing validity of bytes with validity of the label.
from pathlib import Path
for label in json.loads((Path(__file__).resolve().parents[1]/'tests/fixtures/mime-charset-labels.json').read_text()):
 emit('charset-label-'+label,part('Content-Type: text/plain; charset="'+label+'"',b''),'label')
