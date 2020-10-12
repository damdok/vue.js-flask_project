from flask import Flask, jsonify, request, g
from flask_pymongo import PyMongo
from flask_cors import CORS
import time 
import datetime
from functools import wraps
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired, BadSignature
from flask_bcrypt import Bcrypt
# configuration
DEBUG = True

# instantiate the app
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['MONGO_DBNAME'] = 'db_dsf_02'
app.config["MONGO_URI"] = 'mongodb://localhost:27017/db_dsf_02'
mongo = PyMongo(app)
CORS(app, resources={r'/*': {'origins': '*'}}) # enable CORS
app.config['SECRET_KEY'] = "secret"
#-----------AUTH-----------------#
TWO_WEEKS = 86400

SECRET_KEY = app.config['SECRET_KEY']

def generate_token(user, expiration=TWO_WEEKS):
    s = Serializer(SECRET_KEY, expires_in=expiration)
    token = s.dumps({
        'email': user['email'],
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'role': user['role']
    }).decode('utf-8')
    return token


def verify_token(token):
    s = Serializer(SECRET_KEY)
    try:
        data = s.loads(token)
    except (BadSignature, SignatureExpired):
        return None
    return data


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', None)
        if token:
            string_token = token.encode('ascii', 'ignore')
            user = verify_token(string_token)
            if user:
                g.current_user = user
                return f(*args, **kwargs)

        return jsonify(message="Authentication is required to access this resource"), 401

    return decorated
#--------------------------------#

# ----------FUNCTIONS------------#
def setFormatDate(starttime_temp):
    day = str(starttime_temp.day)
    month =str(starttime_temp.month)
    return  day.zfill(2)+ '/' + month.zfill(2) + '/' + str(starttime_temp.year)
    
# ----------ENDPOINTS------------#
#OK
def hashed_password(password):
        return bcrypt.generate_password_hash(password).decode("utf-8")
    
def save_user():
    users = mongo.db.users
    print("================================================================")
    temp_user = users.find_one({"email":"first@last.com"})
    if temp_user is not None:
        return "This user exists. Please enter another email address"
    user = {'first_name':"First","last_name":"Last", 'email':"first@last.com", 'password': hashed_password('password'), 'role' :"Administrator", "doc_type":'DNI', 'doc_number':'1234567890', 'address':'address', 'phone':'0123456789'}
    users.insert_one(user)
    return "User created successfully."

def get_user_with_email_and_password(email, password):
    users = mongo.db.users
    user = users.find_one({"email":email})
    print(user)
    if user and bcrypt.check_password_hash(user['password'], password):
        return user
    else:
        return None

@app.route("/api/is_token_valid", methods=["POST"])
def is_token_valid():
    incoming = request.get_json()
    is_valid = verify_token(incoming["token"])
    if is_valid:
        return jsonify(token_is_valid=True)
    else:
        return jsonify(token_is_valid=False), 403

@app.route("/api/get_token", methods=["POST"])
def get_token():
    incoming = request.get_json()
    user = get_user_with_email_and_password(incoming["email"], incoming["password"])
    print("==================================================   ", user)
    res = {}
    res['success'] = False
    if user != None:
        temp_user = {
            'email': user['email'],
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'role': user['role'],
            'doc_type': user['doc_type'],
            'doc_number': user['doc_number'],
            'address': user['address'],
            'phone': user['phone']
        }
        res['user'] = temp_user
        res['token'] = generate_token(user)
        res['success'] = True
        return res
    res['msg'] = "User not found."
    return res



@app.route('/getanygantt_table', methods=['GET'])
def getanygantt_table():
    datos = mongo.db.anygantt
    lista_resultados = []
    my_dict = {}
    id = 1
    for s in datos.find():
        starttime_temp = datetime.datetime.strptime(s['Start Date'], "%d/%m/%Y")
        finishtime_temp =datetime.datetime.strptime(s['Finish Date'], "%d/%m/%Y")
        baselinestart = datetime.datetime.strptime(s['Baseline Start'], "%d/%m/%Y")
        baselinefinish = datetime.datetime.strptime(s['Baseline Finish'], "%d/%m/%Y")
        my_dict= {'id':id,'owner': s['Owner'],'level':s['Level'],'task': s['Task'],'actualStart': setFormatDate(starttime_temp), 'actualEnd':setFormatDate(finishtime_temp), 'progressValue': s['complete'],'baselinestart':setFormatDate(baselinestart), 'baselinefinish':setFormatDate(baselinefinish)}
        id = id + 1 
        lista_resultados.append(my_dict)
    return jsonify({'data': lista_resultados})

#KO
@app.route('/getanygantt', methods=['GET'])
def getanygantt():
    datos = mongo.db.anygantt
    lista_resultados = []
    my_dict = {}
    id = 1
    for s in datos.find():
        starttime_temp = datetime.datetime.strptime(s['Start Date'], "%d/%m/%Y")
        finishtime_temp =datetime.datetime.strptime(s['Finish Date'], "%d/%m/%Y")
        diff =finishtime_temp - starttime_temp
        my_dict = {}
        process = (float(s['complete'][0:len(s['complete'])-1]))/100
        completed = {}
        color = ""
        if process == 1:
            completed = {
                'amount': 1,
            }
            color = "#0f0"
        elif process > 0:
            completed = {
                'amount':process,
            }
            color = "#00f"            
        else:
            completed ={
                'amount':0,
            }
            color = "#002060"
        if diff.days == 0:
            my_dict= {'id':id,'level':s['Level'],'owner': s['Owner'],'name': s['Task'],'start': starttime_temp,'end':finishtime_temp, 'completed': completed,"duration":diff.days,'milestone':True, 'color':color,'y':id-1, 'duration':diff.days }
        else:
            my_dict= {'id':id,'level':s['Level'],'owner': s['Owner'],'name': s['Task'],'start': starttime_temp,'end':finishtime_temp, 'completed': completed,'color':color, 'y':id -1,'duration':diff.days}
        id = id + 1 
        lista_resultados.append(my_dict)
    return jsonify({'data': lista_resultados})

#OK
@app.route('/getanyganttvisual', methods=['GET'])
def getanyganttvisual():
    datos = mongo.db.anygantt
    save_user()
    lista_resultados = []
    my_dict = {}
    id = 1
    for s in datos.find():
        starttime_temp = datetime.datetime.strptime(s['Start Date'], "%d/%m/%Y")
        finishtime_temp =datetime.datetime.strptime(s['Finish Date'], "%d/%m/%Y")
        basetimelinestart = datetime.datetime.strptime(s['Baseline Start'], "%d/%m/%Y")
        baselinefinish = datetime.datetime.strptime(s['Baseline Finish'], "%d/%m/%Y")
        my_dict = {
            "name":s['Task'],
            'data':[
                {
                    'x':'Work Start',
                    'y':[starttime_temp, finishtime_temp]
                },
                {
                    'x':'BaseLine',
                    'y':[basetimelinestart, baselinefinish]
                }
            ]
        }
        # data_temp= {'id':id,'owner': s['Owner'],'level':s['level'],'task': s['Task'],'actualStart': starttime_temp, 'actualEnd':finishtime_temp, 'progressValue': s['complete'],'baselinestart':s['Baseline Start'], 'baselinefinish':s['Baseline Finish']}
        # id = id + 1 
        lista_resultados.append(my_dict)
    return jsonify({'data': lista_resultados})

@app.route('/kpi_data', methods=['GET'])
def kpi_table():
    datos = mongo.db.kpi_table
    lista_resultados = []
    my_dict = {}
    id = 1
    for s in datos.find():
        starttime_temp = datetime.datetime.strptime(s['first_meeting'], "%d/%m/%Y")
        finishtime_temp =datetime.datetime.strptime(s['decision'], "%d/%m/%Y")
        result =datetime.datetime.strptime(s['result'], "%d/%m/%Y")
        result_target =datetime.datetime.strptime(s['result_target'], "%d/%m/%Y")
        my_dict= {'id':id,'issue': s['issue'],'code':s['code'],'team': s['Team'], 'priority':s['priority'],'status':s['status'],'first_meeting': setFormatDate(starttime_temp), 'decision':setFormatDate(finishtime_temp),'result':setFormatDate(result),'result_target':setFormatDate(result_target), 'r_r_target': s['r_r_target']}
        id = id + 1 
        lista_resultados.append(my_dict)
    return jsonify({'data': lista_resultados})

#OK
@app.route('/kpi_panel', methods=['GET'])
def kpi_panel():
    datos = mongo.db.kpi_table
    lista_resultados = []
    r_target_list = []
    team_list = []
    my_dict = []
    id = 1

    for s in datos.find():
        flg = False
        if s['Team'] not in team_list:
            flg = True
            team_list.append(s['Team'])
        index = team_list.index(s['Team'])
        if index <= len(team_list) -1 and flg == False:
            if s['status'] == 'STARTING':
                my_dict[index][3] +=1
                r_target_list[index][3] += int(s['r_r_target'])
            elif s['status'] == 'IN PROGRESS':
                my_dict[index][2] +=1
                r_target_list[index][2] += int(s['r_r_target'])
            elif s['status'] == 'CLOSE': 
                my_dict[index][1] +=1
                r_target_list[index][1] += int(s['r_r_target'])
            r_target_list[index][4] += int(s['r_r_target'])
        else:
            starting = 0
            progress = 0
            close = 0
            r_starting = 0
            r_progress = 0
            r_close = 0
            if s['status'] == 'STARTING':
                starting = 1
                r_starting = int(s['r_r_target'])
            elif s['status'] == 'IN PROGRESS':
                progress = 1
                r_progress = int(s['r_r_target'])
            elif s['status'] == 'CLOSE': 
                close = 1
                r_close = int(s['r_r_target'])
            temp_list = [s['Team'], close, progress, starting]
            temp_r_list = [s['Team'],r_close,r_progress,r_starting, int(s['r_r_target'])]
            my_dict.append(temp_list)
            r_target_list.append(temp_r_list)
    
    
    r_r_target_list = []
    for r_target in r_target_list:
        r_r_target_list.append({"team":r_target[0], "abs":r_target[4], "value": abs(r_target[4])})
        
    lista_resultados = {
        'issue_list':my_dict,
        'r_r_list':r_target_list,
        'Team_list':team_list,
        'r_r_target_list':r_r_target_list
    }
    return jsonify({'data': lista_resultados})

if __name__ == '__main__':
    app.run(debug=True)