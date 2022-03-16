from __future__ import print_function, absolute_import, unicode_literals
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor
from cryptography.fernet import Fernet
from flask import *
from sqltasks import *
from otp import *
from os import path
from datetime import *
import shortuuid
import pickle
import string
import random
import os

url="rproxymaster.eastus.cloudapp.azure.com" 
app = Flask(__name__, static_url_path="")

filepth='/home/vm_user/Reverse_Proxy/userfiles/'

if not path.exists(filepth+'rproxyseckey.pkl'):
	outp3=open(filepth+'rproxyseckey.pkl','wb')
	pickle.dump(os.urandom(32),outp3,pickle.HIGHEST_PROTOCOL)
	outp3.close()

inp3=open(filepth+'rproxyseckey.pkl', 'rb')
app.secret_key = pickle.load(inp3)

rp = PublicKeyCredentialRpEntity(url, "Demo server")
server = Fido2Server(rp)

if not path.exists(filepth+'fernetkey1.pkl'):
	with open(filepth+'fernetkey1.pkl','wb') as outp1:
		pickle.dump(Fernet.generate_key(),outp1,pickle.HIGHEST_PROTOCOL)

if not path.exists(filepth+'fernetkey2.pkl'):
	with open(filepth+'fernetkey2.pkl','wb') as outp2:
		pickle.dump(Fernet.generate_key(),outp2,pickle.HIGHEST_PROTOCOL)
createTable()
createStudentTable()
createTokenTable()

alphabet = string.ascii_lowercase + string.digits
su = shortuuid.ShortUUID(alphabet=alphabet)

inp1=open(filepth+'fernetkey1.pkl', 'rb')
key1=pickle.load(inp1)
inp2=open(filepth+'fernetkey2.pkl', 'rb')
key2=pickle.load(inp2)
f1=Fernet(key1)
f2=Fernet(key2)
credentials = []

dtformat="%Y-%m-%d-%H-%M-%S"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/reg")
def reg():
	return render_template("getreg.html")

@app.route("/reginit", methods=["POST"])
def reginit():
	try:
		rnum=request.form['rnum']
		rnum=rnum.strip()
		o=genOtp()
		em=getEmail(rnum)
		print(rnum)
		print(o)
		print(em)
		t1=f1.encrypt(rnum.encode()).decode()
		t2=f2.encrypt(o.encode()).decode()
		print(t1)
		print(t2)
		sendEmail(em,o)
		return render_template("otpauth.html",token1=t1,token2=t2)
	except:
		return render_template("error.html",reason='Registration number does not exist. Contact admin.')

@app.route("/markattendance", methods=["GET"])
def markattendance():
	token=request.args.get('classId')
	cid=getCidFromToken(token)
	tm=getTimeFromToken(token)
	if timeValid(tm):
		rnum=request.cookies.get('rnum')
		return render_template("authenticate.html",rnum=rnum, cid=cid)
	else:
		return render_template("error.html", reason='QR Code expired')
	
@app.route("/attendance")
def attendance():
	return render_template("authenticatelegacy.html")
	
@app.route("/markattendancelegacy", methods=["POST"])
def markattendancelegacy():
	classid=request.form['cid']
	rnum=request.form['rnum']
	resp=make_response(render_template("authenticate.html",rnum=rnum, cid=classid))
	resp.set_cookie('rnum',rnum,max_age=60*60*24*365*8)
	return resp
	
@app.route("/downloadattendance", methods=["GET"])
def downloadattendance():
	classid=request.args.get('classId')
	res=getReg_nobyclass_id(classid)
	output=make_response(res)
	output.headers["Content-Disposition"] = "attachment; filename=attendance_"+classid+".csv"
	output.headers["Content-type"] = "text/csv"
	return output
	
@app.route("/getportal")
def getportal():
	cid='0'
	try:
		cidcook=request.cookies.get('cid')
		if cidcook is None:
			cid='0'
		else:
			cid=cidcook
	except:
		cid='0'
	setcookies=0
	if cid=='0':
		setcookies=1
		cidn=random.randint(0,999999)
		cid=str(cidn)
	now=datetime.now()
	nowstr=now.strftime(dtformat)
	
	uid=su.random(length=8)
	addToken(cid,nowstr,uid)

	if setcookies==0:
		return render_template("instructor.html",url=url,cid=uid, cidplain=cid)
	else:
		resp=make_response(render_template("instructor.html",url=url,cid=uid,cidplain=cid))
		resp.set_cookie('cid',cid)
		return resp
		
@app.route("/attendanceportal")
def attendanceportal():
	resp=make_response(redirect("/getportal"))
	resp.set_cookie('cid',0)
	return resp
	
@app.route("/resumeportal")
def resumeportal():
	return render_template("resumeinstructor.html")
	
@app.route("/resumeportalpage", methods=["POST"])
def resumeportalpage():
	cid=request.form['cid']
	return render_template("instructor.html",url=url,cid=cid)
	
@app.route("/otpcheck", methods=["POST"])
def otpcheck():
	otp=request.form['otp']
	t1=request.form['t1'].strip().encode()
	t2=request.form['t2'].strip().encode()
	print(t1)
	print(t2)
	rnum=f1.decrypt(t1).decode()
	cotp=f2.decrypt(t2).decode()
	if otp.strip()==cotp.strip():
		print(rnum)
		resp = make_response(render_template('register.html',rnum=rnum))
		resp.set_cookie('rnum',rnum,max_age=60*60*24*365*8)
		return resp
	else:
		return render_template("error.html", reason='Incorrect OTP.')
	
@app.route("/success")
def success():
	return render_template("success.html")
	
@app.route("/univdb")
def univdb():
    return render_template("univdb.html")
    
@app.route("/univdbupload", methods=["POST", "GET"])
def univdbupload():
    try:
        if request.method == 'POST':
          f = request.files['file']
          k=f.read().decode().splitlines()
          for x in k:
              r=x.split(",")
              for em in r:
                 em=em.strip()
                 if '@' in em:
                     print(em)
                     addStudent(em)
        return redirect("/success")
    except:
	return render_template("error.html",reason='No file uploaded or corrupted file.')

	
@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    user = request.args.get('nm')
    print(user)
    credentials=readkey(user)
    registration_data, state = server.register_begin(
        {
            "id": b"user_id",
            "name": user,
            "displayName": user,
            "icon": "https://example.com/image.png",
        },
        credentials,
        user_verification="discouraged",
        authenticator_attachment="platform",
    )

    session["state"] = state
    print("\n\n\n\n")
    print(registration_data)
    print("\n\n\n\n")
    return cbor.encode(registration_data)


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    user = request.args.get('nm')
    print(user)
    credentials=readkey(user)
    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])
    print("clientData", client_data)
    print("AttestationObject:", att_obj)
    auth_data = server.register_complete(session["state"], client_data, att_obj)
    credentials.append(auth_data.credential_data)
    savekey(credentials,user)
    print("REGISTERED CREDENTIAL:", auth_data.credential_data)
    return cbor.encode({"status": "OK"})


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    user = request.args.get('nm')
    print(user)
    credentials=readkey(user)

    if not credentials:
        abort(404)

    auth_data, state = server.authenticate_begin(credentials)
    session["state"] = state
    return cbor.encode(auth_data)

@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    user = request.args.get('nm')
    classid=request.args.get('cid')
    print(user)
    print(classid)
    credentials=readkey(user)
    if not credentials:
        abort(404)

    data = cbor.decode(request.get_data())
    credential_id = data["credentialId"]
    client_data = ClientData(data["clientDataJSON"])
    auth_data = AuthenticatorData(data["authenticatorData"])
    signature = data["signature"]
    print("clientData", client_data)
    print("AuthenticatorData", auth_data)

    server.authenticate_complete(
        session.pop("state"),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature,
    )
    print("ASSERTION OK")
    
    print("\n\n")
    print("Attendance marking for "+user+" in class "+classid);
    addUser(user,classid)    
    return cbor.encode({"status": "OK"})
    
def timeValid(tmstr):
	now=datetime.now()
	dtm=datetime.strptime(tmstr,dtformat)
	expdt=dtm+timedelta(seconds=15) #Seconds to scan
	k=expdt>=now
	return k
    
def savekey(credentials,user):
	with open(filepth+user+'datafilekey.pkl','wb') as outp1:
		pickle.dump(credentials,outp1,pickle.HIGHEST_PROTOCOL)
		
def readkey(user):
	print(user)
	try:
		with open(filepth+user+'datafilekey.pkl', 'rb') as inp:
			temp = pickle.load(inp)
			print("Data read")
			#print(credentials)
			return temp
	except:
		print("no cred data")
		return []


if __name__ == "__main__":
	context = ('server.crt', 'server.key')
	app.run(ssl_context=context, debug=False, host="0.0.0.0", port=8080)
