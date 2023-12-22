from fastapi import FastAPI, UploadFile, HTTPException, File
from fastapi.responses import FileResponse
import shutil
import pymysql as sql
import threading
import time
import random
import hashlib
import os

# Setting
dbHost = "192.168.0.11"
dbUsr = "yara"
dbPwd = "7QhMQ7mBB7dGs2AY"
dbName = "yara"


#初始化API
Api = FastAPI()
#创建数据库锁
sqlLock = threading.Lock()
#连接数据库
try:
    with sqlLock:
        dbCon = sql.connect(host=dbHost,user=dbUsr,password=dbPwd,database=dbName)
    print(" \033[42m[S]\033[0m " + f"已登录到{dbUsr}@{dbHost}")
except sql.Error as e:
    print (" \033[45m[F]\033[0m " + f"无法登录到{dbUsr}@{dbHost}: {e}")
    exit

## 任务添加申请
@Api.get("/task/add", status_code=201)
def read_item(hash:str):
    id = 0
    feedbackCode = 0
    feedbackMessage = ""

    #数据库刷新
    with sqlLock:
        dbCon.commit()
        dbCur = dbCon.cursor()

    # 安全校验
    if len(hash) != 32:
        raise HTTPException(status_code=400, detail="Couldn't pass Secure Check: Not a vaild Hash")
    try:
        int(hash, 16)
    except ValueError:
        raise HTTPException(status_code=400, detail="Couldn't pass Secure Check: Not a vaild Hash")
    
    # 已有的任务但是没有超过5分钟
    with sqlLock:
        dbCur.execute("SELECT * FROM `task` WHERE hash = %s AND status != 'Done' AND addTime >= %s ;", (hash, int(time.time())-300))
    inListTask = list(dbCur.fetchall())
    if len(inListTask) > 0:
        raise HTTPException(status_code=423, detail="The same file has been uploaded by other users, please wait for the file scanning to complete")
    
    #清理已有的任务但是超过了5分钟但状态还是NoFile
    with sqlLock:
        dbCur.execute("DELETE FROM `task` WHERE hash = %s AND status != 'Done' AND addTime < %s ;", (hash, str(int(time.time())-300)))
        dbCon.commit()

    #添加任务
    if feedbackCode == 0:
        # 生成id
        id = int(str(int(time.time()))+str(random.randint(100,999))) # 时间后跟三位随机数
        # 写入db
        try:
            with sqlLock:
                dbCur.execute("INSERT INTO task(id, hash, status, addTime, startTime, endTime, matchs) VALUES (%s, %s, %s, %s, %s, %s, %s)", (id, hash, 'NoFile', str(int(time.time())), 0, 0,'na'))
                dbCon.commit()
            feedbackMessage = "已添加"
        except:
            id = 0
            feedbackCode = -1
            feedbackMessage = "ERROR: 任务写入数据库失败" 
            raise HTTPException(status_code=500, detail="Database Error")


    # json数据包
    data = {
        "packageVersion": 1,
        "time": int(time.time()),
        "taskApply": {
            "code": feedbackCode,
            "message": feedbackMessage,
            "id": id
        }
    }
    return data


## 任务状态查询
@Api.get("/task/status")
def read_item(id:int):
    feedbackCode = 0
    feedbackMessage = ""
    feedbackStatus = "na"
    feedbackId = 0
    feedbackHash = "na"
    feedbackAddTime = 0
    feedbackStartTime = 0
    feedbackEndTime = 0
    feedbackMatchs = []

    # 输入检查
    try:
        int(id)
    except ValueError:
        feedbackCode = -1
        feedbackMessage = "Refuse: 非法的MD5输入"
        raise HTTPException(status_code=400, detail="Couldn't pass Secure Check")

    # 查询任务状态
    if feedbackCode == 0:
        with sqlLock:
            # 读取db
            dbCur = dbCon.cursor()
            dbCur.execute("SELECT * FROM `task` WHERE id = %s;", (id))
            sqlFeedback = list(dbCur.fetchall())
            # 任务是否存在
            if len(sqlFeedback)>0:
                # 读取db返回信息
                feedbackId = sqlFeedback[0][0]
                feedbackStatus = sqlFeedback[0][1]
                feedbackAddTime = sqlFeedback[0][2]
                feedbackStartTime = sqlFeedback[0][3]
                feedbackEndTime = sqlFeedback[0][4]
                feedbackHash = sqlFeedback[0][5]
                
                # 单独处理matchs
                originData_Matchs = sqlFeedback[0][6]
                feedbackMatchs = originData_Matchs.split("&")
                feedbackMatchs = feedbackMatchs[:-1]
            else:
                feedbackCode = -1
                feedbackMessage = "Refuse: 不存在的任务id"
                raise HTTPException(status_code=404, detail="Not Found")

    data = {
    "packageVersion": 1,
    "time": int(time.time()),
    "taskStatus":{
        "code":feedbackCode,
        "message":feedbackMessage,
        "status":feedbackStatus,
        "id":feedbackId,
        "hash":feedbackHash,
        "addTime":feedbackAddTime,
        "startTime":feedbackStartTime,
        "endTime":feedbackEndTime,
        "matchs":feedbackMatchs
        }
    }
    
    return data

## 文件接收
@Api.post("/file")
async def upload_file(id:int, file: UploadFile = File(...)):
    # 安全检查
    try:
        int(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Couldn't pass Secure Check")
    
    # 请求上传文件的任务id是否存在
    with sqlLock:
        dbCur = dbCon.cursor()
        dbCur.execute("SELECT * FROM `task` WHERE id = %s AND status = 'NoFile' ;", (id))
    inListTask = list(dbCur.fetchall())
    if len(inListTask) == 0:
        raise HTTPException(status_code=400, detail="Unknown id or Upload pipe has been closed")

    # 文件大小限制
    if file.file._file.tell() > 50 * 1024 * 1024:  # 如果文件大于50MB
        raise HTTPException(status_code=413, detail="File is too large")
    
    # 查询任务基本信息
    with sqlLock:
        dbCur.execute("SELECT * FROM `task` WHERE id = %s' ;", (id))
    inListTask = list(dbCur.fetchall())
    taskHash = inListTask[0][5]

    #接受数据
    try:
        with open(f"./ScanFile/{taskHash}", "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except:
        raise HTTPException(status_code=500, detail="Server I/O Error")
    
    #数据校验
    md5Hash = hashlib.md5
    while md5Hash := buffer.read(8192):
        md5Hash.update(md5Hash)
    fileHash = md5Hash.hexdigest()
    if fileHash != taskHash:
        raise HTTPException(status_code=400, detail="File may damaged")
    
    #更新任务状态
    with sqlLock:
        dbCur.execute(f"UPDATE task SET status = 'InList' WHERE id = {id};")
        dbCon.commit()
    
    return()