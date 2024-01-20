import pymysql as sql
import time
import YaraAction as engine
import threading
import platform
import yara
import os
import configparser

print ("\033[44m== Yara Engine API Project ==========\033[0m")
print ("\033[44mSystem: " + platform.platform() + "\033[0m")
print ("\033[44mPyVersion: " + platform.python_version() + "\033[0m")
print ("\033[44mCopyright © 2023 Shutdown & Kolomina, All rights reserved.\033[0m")
print ()



# 读取配置
def configReader():
    global scannerMaxThread,dbHost,dbUsr,dbPwd,dbName

    try:
        config = configparser.read("./setting.ini")
    except configparser.Error as e:
        print(" \033[41m[E]\033[0m " + f"在读取setting.ini时出现错误: {e}")
        exit()
    
    scannerRule = config.items("scanner")
    scannerRule = dict(scannerRule)
    scannerMaxThread = scannerRule["thread"] #最大线程

    configSql = config.items("sql")
    configSql = dict(configSql)
    dbHost = configSql["host"] #数据库服务器
    dbUsr = configSql["user"] #数据库用户
    dbPwd = configSql["password"] #数据库密码
    dbName = configSql["name"] #数据库名字



##线程启动器
def ThreadStarter(startTotal, taskList):
    startingThread = 0

    with sqlLock:
        dbCur = dbCon.cursor()
    for startingThread in range(startTotal):
        #从sql返回结果截取信息
        selectId = int(taskList[startingThread][0])
        selectHash = str(taskList[startingThread][5])

        #更新任务状态
        with sqlLock:
            dbCur.execute(f"UPDATE task SET status = 'Scanning' WHERE id = {selectId};")
            dbCur.execute(f"UPDATE task SET startTime = '{int(time.time())}' WHERE id = {selectId};")
            dbCon.commit()

        #创建线程
        scanThread = threading.Thread(target=engine.YaraMatch, args=(selectId,scanFilePath+"/"+selectHash, engineRules,dbCon,sqlLock))
        scanThread.start()



##计划任务
def EventClock():
    print(" \033[42m[S]\033[0m " + "✅Controller计划任务已处于活跃状态")
    with sqlLock:
        dbCur = dbCon.cursor()
    # 有没有新任务
    while True:
        time.sleep (5)
        with sqlLock:
            dbCon.commit()
            dbCur.execute("SELECT * FROM `file` WHERE status = 'InList';")
        inListTask = list(dbCur.fetchall())
        # 还有没有空闲线程
        if len(inListTask) > 0:
            with sqlLock:
                dbCur.execute("SELECT * FROM `file` WHERE status = 'Scanning';")
            scanningTask = list(dbCur.fetchall())
            freeThread = scannerMaxThread - len(scanningTask)
            #判断开几个线程
            if freeThread<len(inListTask):
                startTotal=freeThread
            else:
                startTotal=len(inListTask)
            ThreadStarter(startTotal=startTotal, taskList=inListTask)



# 载入配置
configReader()

# 登录数据库
sqlLock = threading.Lock()#创建锁
try:
    with sqlLock:
        dbCon = sql.connect(host=dbHost,user=dbUsr,password=dbPwd,database=dbName)
    print(" \033[42m[S]\033[0m " + f"已登录到{dbUsr}@{dbHost}")
except sql.Error as e:
    print (" \033[45m[F]\033[0m " + f"无法登录到{dbUsr}@{dbHost}: {e}")
    exit()

# 重置所有Scanning状态的任务
try:
    with sqlLock:
        dbCur = dbCon.cursor()
        dbCur.execute(f"UPDATE file SET status = 'InList' WHERE status = 'Scanning';")
        dbCon.commit()
except:
    print(" \033[43m[W]\033[0m " + f"无法重设所有Scanning状态的任务，未重置的任务可能会被遗弃！")

# 进入计划任务
EventClock()