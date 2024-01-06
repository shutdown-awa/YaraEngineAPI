import pymysql as sql
import time
import YaraAction as engine
import threading
import platform
import yara
import os

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
scanFilePath = "/workspaces/python/YaraEngineAPI/backend/ScanFile/"
ruleOriginPath = "/workspaces/python/YaraEngineAPI/backend/RuleOrigin"
ruleCompiledPath = "/workspaces/python/YaraEngineAPI/backend/RuleCompiled/"

## PREP
sqlLock = threading.Lock()#创建锁
# 登录数据库
try:
    with sqlLock:
        dbCon = sql.connect(host=dbHost,user=dbUsr,password=dbPwd,database=dbName)
    print(" \033[42m[S]\033[0m " + f"已登录到{dbUsr}@{dbHost}")
except sql.Error as e:
    print (" \033[45m[F]\033[0m " + f"无法登录到{dbUsr}@{dbHost}: {e}")
    exit()



## INIT
def __init__():
    #文件路径check
    if (os.path.exists(scanFilePath) == False):#待扫描文件的路径
        print (" \033[45m[F]\033[0m " + f"不存在的scanFile目录: {scanFilePath}")
        exit()
    if (os.path.exists(ruleOriginPath) == False):#待扫描文件的路径
        print (" \033[45m[F]\033[0m " + f"不存在的ruleOriginPath目录: {ruleOriginPath}")
        exit()
    if (os.path.exists(ruleCompiledPath) == False):#待扫描文件的路径
        print (" \033[45m[F]\033[0m " + f"不存在的ruleCompiledPath目录: {ruleCompiledPath}")
        exit()

    try:
        #重置所有Scanning状态的任务
        with sqlLock:
            dbCur = dbCon.cursor()
            dbCur.execute(f"UPDATE task SET status = 'InList' WHERE status = 'Scanning';")
            dbCon.commit()
    except:
        print(" \033[43m[W]\033[0m " + f"无法重设所有Scanning状态的任务，未重置的任务可能会被遗弃！")

    #编译规则
    YaraRuleCompile(ruleOriginPath,ruleCompiledPath)

    #进入事件
    EventClock()



## 规则编译器
def YaraRuleCompile(src_dir, dest_dir):
    print(" \033[47m[I]\033[0m " + "现在开始预编译规则😋")
    # 遍历源目录
    for filename in os.listdir(src_dir):
        # 检查文件是否以.yar结尾
        if filename.endswith('.yar'):
            # 获取文件的完整路径
            file_path = os.path.join(src_dir, filename)
            try:
                # 使用yara编译规则文件
                rules = yara.compile(filepath=file_path)
                # 将编译后的规则保存到目标目录
                rules.save(os.path.join(dest_dir, filename))
            except yara.Error as e:
                print(" \033[41m[E]\033[0m " + f"在编译规则 {file_path} 时出现错误: {e}")
                continue
    print(" \033[42m[S]\033[0m " + "预编译已完成😋")



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
    print(" \033[42m[S]\033[0m " + "✅计划任务已处于活跃状态")
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



__init__()