import pymysql as sql
import time
import YaraAction as engine
import threading
import platform

print ("\033[44m== Yara Engine API Project ==========\033[0m")
print ("\033[44mModule: Controller_Module\033[0m")
print ("\033[44mSystem: " + platform.platform() + "\033[0m")
print ("\033[44mPyVersion: " + platform.python_version() + "\033[0m")
print ("\033[44mCopyright © 2023 Shutdown & Kolomina, All rights reserved.\033[0m")
print ()

# Setting
dbHost = "192.168.0.11"
dbUsr = "yara"
dbPwd = "7QhMQ7mBB7dGs2AY"
dbName = "yara"
maxThread = 6
scanFilePath = "./ScanFile"
rulePath = "./RuleCompiled"

#创建锁
sqlLock=threading.Lock()

# 登录数据库
try:
    with sqlLock:
        dbCon = sql.connect(host=dbHost,user=dbUsr,password=dbPwd,database=dbName)
    print(" \033[42m[S]\033[0m " + f"已登录到{dbUsr}@{dbHost}")
except sql.Error as e:
    print (" \033[45m[F]\033[0m " + f"无法登录到{dbUsr}@{dbHost}: {e}")
    exit


#线程启动器
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


##定时
def Main():
    with sqlLock:
        dbCur = dbCon.cursor()
    # 有没有新任务
    while True:
        time.sleep (5)
        with sqlLock:
            dbCon.commit()
            dbCur.execute("SELECT * FROM `task` WHERE status = 'InList';")
        inListTask = list(dbCur.fetchall())
        # 还有没有空闲线程
        if len(inListTask) > 0:
            with sqlLock:
                dbCur.execute("SELECT * FROM `task` WHERE status = 'Scanning';")
            scanningTask = list(dbCur.fetchall())
            freeThread = maxThread - len(scanningTask)
            #判断开几个线程
            if freeThread<len(inListTask):
                startTotal=freeThread
            else:
                startTotal=len(inListTask)
            ThreadStarter(startTotal=startTotal, taskList=inListTask)


# 编译规则
import Tools
Tools.compile_yara_rules("./RuleOrigin", "./RuleCompiled")
#载入规则
engineRules = engine.YaraRuleLoad(rulePath)
# 将所有的Scanning重置为InList，重新扫描
with sqlLock:
    dbCur = dbCon.cursor()
    dbCur.execute("UPDATE `task` SET status = 'InList' WHERE status = 'Scanning';")
# 载入
Main()