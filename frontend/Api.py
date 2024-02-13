from fastapi import FastAPI, UploadFile, HTTPException, File
import shutil
import pymysql as sql
import threading
import time
import random
import hashlib
import os
import platform
import configparser

print("\033[44m== Yara Engine API Project ==========\033[0m")
print("\033[44mModule: Api Service\033[0m")
print("\033[44mSystem: " + platform.platform() + "\033[0m")
print("\033[44mPyVersion: " + platform.python_version() + "\033[0m")
print("\033[44mCopyright © 2023 Shutdown & Kolomina, All rights reserved.\033[0m")
print("⛔️ \033[41mThis is a preview version for insider, DO NOT share this to any people.\033[0m")
print()



def configReader():
    global dbHost, dbUsr, dbPwd, dbName, scanFilePath

    # Open setting.ini
    try:
        config = configparser.ConfigParser()
        config.read(os.path.dirname(os.path.abspath(__file__)) + "/setting.ini")
    except configparser.Error as e:
        print(" \033[41m[E]\033[0m " + f"在读取setting.ini时出现错误: {e}")
        exit()

    # Load database config
    configSql = config.items("sql")
    configSql = dict(configSql)
    dbHost = configSql["host"]  # 数据库服务器
    dbUsr = configSql["user"]  # 数据库用户
    dbPwd = configSql["password"]  # 数据库密码
    dbName = configSql["name"]  # 数据库名字

    configPath = config.items("path")
    configPath = dict(configPath)
    scanFilePath = configPath["file_dir"]



# 读取配置
configReader()
# 初始化API
app = FastAPI()
# 创建数据库锁
sqlLock = threading.Lock()
# 连接数据库
try:
    with sqlLock:
        dbCon = sql.connect(host=dbHost, user=dbUsr, password=dbPwd, database=dbName)
    print(" \033[42m[S]\033[0m " + f"已登录到{dbUsr}@{dbHost}")
except sql.Error as e:
    print(" \033[45m[F]\033[0m " + f"无法登录到{dbUsr}@{dbHost}: {e}")
    exit



# 任务添加请求
@app.get("/task/add", status_code=201)
def read_item(hash: str):
    id = 0
    feedbackCode = 0
    feedbackMessage = ""

    # 数据库刷新
    with sqlLock:
        dbCon.commit()
        dbCur = dbCon.cursor()

    # 安全校验
    if len(hash) != 32:
        raise HTTPException(
            status_code=400, detail="Couldn't pass Secure Check: Not a vaild Hash. (Type: A)")
    try:
        int(hash, 16)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Couldn't pass Secure Check: Not a vaild Hash. (Type: B)")

    # 格式化md5输入
    hash = hash.lower()

    # 是否需要在File表加入新的任务
    try:
        with sqlLock:
            dbCur = dbCon.cursor()
            dbCur.execute("SELECT * FROM `file` WHERE hash = %s;", (hash))
            sqlFeedback = list(dbCur.fetchall())
    except:
        feedbackCode = -2
        feedbackMessage = "SQL Error"
        raise HTTPException(
            status_code=400, detail=f"{feedbackMessage} ({feedbackCode})")

    if len(sqlFeedback) == 0:
        try:
            with sqlLock:
                dbCur.execute("INSERT INTO `file`(hash, status, matchs, timestamp, rule_version) VALUES (%s, %s, %s, %s, %s)",
                              (hash, 'NoFile', 'na', 0, 0))
                dbCon.commit()
            feedbackMessage = "已添加"
        except:
            print(" \033[43m[E]\033[0m " + f"未能存储文件信息：{dbCon.Error()}")
            raise HTTPException(status_code=500, detail="Database Error")

    # 添加任务信息到task表
    if feedbackCode == 0:
        # 保存时间
        timestamp = str(int(time.time()))
        # 生成id
        id = timestamp + str(random.randint(111, 999))  # 时间后跟三位随机数
        # 写入db
        try:
            with sqlLock:
                dbCur.execute("INSERT INTO task(id, hash, timestamp) VALUES (%s, %s, %s)",
                              (id, hash, timestamp))
                dbCon.commit()
            feedbackMessage = "已添加"
        except:
            print(" \033[43m[E]\033[0m " + f"未能存储任务：{dbCon.Error()}")
            raise HTTPException(status_code=500, detail="Database Error")

    # json数据包
    data = {
        "packageVersion": 1,
        "time": int(time.time()),
        "taskApply": {
            "code": feedbackCode,
            "message": feedbackMessage,
            "id": id,
            "timestamp": timestamp,
            "hash": hash
        }
    }
    return data


# 任务状态查询
@app.get("/task/status")
def read_item(id: int):
    feedbackCode = 0
    feedbackMessage = ""
    taskStatus = "na"
    taskId = 0
    taskHash = "na"
    taskAddTimestamp = 0
    taskEndTimestamp = 0
    taskMatchs = []

    # 输入检查
    try:
        int(id)
    except ValueError:
        feedbackCode = -1
        feedbackMessage = "Refuse: 非法的ID输入"
        raise HTTPException(
            status_code=400, detail="Couldn't pass Secure Check. (Type: B)")

    # Sync Db
    try:
        with sqlLock:
            dbCon.commit()
    except:
        feedbackCode = -2
        feedbackMessage = "SQL Error"
        raise HTTPException(
            status_code=400, detail=f"{feedbackMessage} ({feedbackCode})")

    # 查询任务状态
    try:
        with sqlLock:
            # 读取task表
            dbCur = dbCon.cursor()
            dbCur.execute("SELECT hash, id, timestamp FROM `task` WHERE id = %s;", (id))
            taskTableFeedback = list(dbCur.fetchall())
    except:
        feedbackCode = -2
        feedbackMessage = "SQL Error"
        raise HTTPException(
            status_code=400, detail=f"{feedbackMessage} ({feedbackCode})")

    # 任务是否存在
    if len(taskTableFeedback) <= 0:
        feedbackCode = -1
        feedbackMessage = "Refuse: 不存在的任务id"
        raise HTTPException(status_code=404, detail="Not Found")

    # 读取task表返回信息
    taskHash = taskTableFeedback[0][0]
    taskId = taskTableFeedback[0][1]
    taskAddTimestamp = taskTableFeedback[0][2]
    
    # 读取file表
    try:
        with sqlLock:
            dbCur.execute("SELECT matchs, rule_version, status FROM `file` WHERE `hash` = %s;", (taskHash))
            fileTableFeedback = list(dbCur.fetchall())
    except:
        feedbackCode = -2
        feedbackMessage = "SQL Error"
        raise HTTPException(
            status_code=400, detail=f"{feedbackMessage} ({feedbackCode})")
    # 处理file表信息
    taskMatchs = fileTableFeedback[0][0]
    taskRuleVersion = fileTableFeedback[0][1]
    taskStatus = fileTableFeedback[0][2]

    feedbackCode = 0
    feedbackMessage = "获取成功"

    data = {
        "packageVersion": 1,
        "time": int(time.time()),
        "taskStatus": {
            "code": feedbackCode,
            "message": feedbackMessage,
            "status": taskStatus,
            "id": taskId,
            "hash": taskHash,
            "addTime": taskAddTimestamp,
            "endTime": taskEndTimestamp,
            "matchs": taskMatchs,
            "rule_version": taskRuleVersion
        }
    }

    return data


# 文件接收
@app.post("/file")
async def upload_file(id: int, file: UploadFile = File(...)):
    # 安全检查
    try:
        int(id)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Couldn't pass Secure Check (Type: B)")

    # Sync Db
    try:
        with sqlLock:
            dbCon.commit()
    except:
        feedbackCode = -2
        feedbackMessage = "SQL Error"
        raise HTTPException(
            status_code=400, detail=f"{feedbackMessage} ({feedbackCode})")

    # 查询任务状态
    try:
        with sqlLock:
            # 读取task表
            dbCur = dbCon.cursor()
            dbCur.execute("SELECT hash FROM `task` WHERE id = %s;", (id))
            taskTableFeedback = list(dbCur.fetchall())
    except:
        feedbackCode = -2
        feedbackMessage = "SQL Error"
        raise HTTPException(
            status_code=400, detail=f"{feedbackMessage} ({feedbackCode})")

    # 任务是否存在
    if len(taskTableFeedback) < 0:
        feedbackCode = -1
        feedbackMessage = "Refuse: 不存在的任务id"
        raise HTTPException(status_code=404, detail="Not Found")

    # 读取task表返回信息
    taskHash = taskTableFeedback[0][0]
    
    # 读取file表
    try:
        with sqlLock:
            dbCur.execute("SELECT status FROM `file` WHERE `hash` = %s;", (taskHash))
            fileTableFeedback = list(dbCur.fetchall())
    except:
        feedbackCode = -2
        feedbackMessage = "SQL Error"
        raise HTTPException(
            status_code=400, detail=f"{feedbackMessage} ({feedbackCode})")
    # 处理file表信息
    taskStatus = fileTableFeedback[0][0]

    # 是否适合上传的状态？
    # 检查服务器是否已经保存了这个文件
    if (os.path.exists(scanFilePath + "/" + taskHash)):
        # 顺便刷新任务状态
        try:
            with sqlLock:
                dbCur.execute(
                    "UPDATE `file` SET status = 'InList' WHERE status = 'NoFile' AND hash = %s;", taskHash)
        except:
            feedbackCode = -2
            feedbackMessage = "SQL Error"
            raise HTTPException(
                status_code=400, detail=f"{feedbackMessage} ({feedbackCode})")

        raise HTTPException(
            status_code=400, detail="Server has already save this file which with the same Hash.")
    # 检查Status是否合适
    if (taskStatus != "NoFile"):
        raise HTTPException(
            status_code=400, detail="Upload pipe isn't opening.")


    # 写入数据
    try:
        with open(f"{scanFilePath}/{taskHash}", "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except:
        raise HTTPException(status_code=500, detail="Server I/O Error")
    buffer.close()

    # 数据校验
    with open(f"{scanFilePath}/{taskHash}", "rb") as f:
        file_hash = hashlib.md5()
        while chunk := f.read(8192):
            file_hash.update(chunk)
    fileHash = file_hash.hexdigest()
    if fileHash != taskHash:
        os.remove(f"{scanFilePath}/{taskHash}")
        raise HTTPException(status_code=400, detail="File may damaged")

    # 更新任务状态
    with sqlLock:
        dbCur.execute("UPDATE `file` SET status = 'InList' WHERE hash = %s;", (taskHash))
        dbCon.commit()

    raise HTTPException(status_code=201, detail="Created")
