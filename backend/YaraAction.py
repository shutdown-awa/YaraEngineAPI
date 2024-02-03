import yara
import os
import pymysql as sql
import time
import threading
import configparser


## 读取配置
try:
    config = configparser.ConfigParser()
    config.read(os.path.dirname(os.path.abspath(__file__)) + "/setting.ini")
except configparser.Error as e:
    print(" \033[41m[E]\033[0m " + f"在读取setting.ini时出现错误: {e}")
    exit()

configRule = config.items("rule")
configRule = dict(configRule)
configRuleOriginDir = configRule["src_dir"] #yara规则编译目录
configRuleCompileDir = configRule["dest_dir"] #yara规则编译目录

configSql = config.items("sql")
configSql = dict(configSql)
dbHost = configSql["host"] #数据库服务器
dbUsr = configSql["user"] #数据库用户
dbPwd = configSql["password"] #数据库密码
dbName = configSql["name"] #数据库名字

configScanner = config.items("scanner")
configScanner = dict(configScanner)
configFileDir = configScanner["file_dir"]

## PREP
sqlLock = threading.Lock()#创建锁

## 登录数据库
try:
    with sqlLock:
        dbCon = sql.connect(host=dbHost,user=dbUsr,password=dbPwd,database=dbName)
    print(" \033[42m[S]\033[0m " + f"已登录到{dbUsr}@{dbHost}")
except sql.Error as e:
    print (" \033[45m[F]\033[0m " + f"无法登录到{dbUsr}@{dbHost}: {e}")
    exit()



## 规则编译器
def YaraRuleCompile():
    # 获取版本信息
    versionInfoAtSrc = open(configRuleOriginDir + "/version", 'r').read()
    versionInfoAtDst = open(configRuleCompileDir + "/version", 'r').read()
    if versionInfoAtSrc == versionInfoAtDst:
        return
    
    print("发现规则更新🥳！重新编译🔨🔨🔨🔨!")
    # 遍历源目录
    for filename in os.listdir(configRuleOriginDir):
        # 检查文件是否以.yar结尾
        if filename.endswith('.yar'):
            # 获取文件的完整路径
            file_path = os.path.join(configRuleOriginDir, filename)
            try:
                # 使用yara编译规则文件
                rules = yara.compile(filepath=file_path)
                # 将编译后的规则保存到目标目录
                rules.save(os.path.join(configRuleCompileDir, filename))
            except yara.Error as e:
                print(" \033[41m[E]\033[0m " + f"在编译规则 {file_path} 时出现错误: {e}")
                continue

    #更新版本信息
        open(configRuleCompileDir + "/version", 'w').write(versionInfoAtSrc)



## 加载规则
def YaraRuleLoad():
    global rules, ruleVersion #创建全局变量

    for root, dirs, files in os.walk(configRuleCompileDir):
        for file in files:
            if file.endswith('.yar'):
                filepath = os.path.join(root, file)
                try:
                    rules = yara.load(filepath)
                except yara.Error as e:
                    print(" \033[41m[E]\033[0m " + f"在载入规则 {filepath} 时出现错误: {e}")
    print(" \033[42m[S]\033[0m " + "👀规则现已全部载入内存")
    ruleVersion = open(configRuleCompileDir + "/version", 'r').read()



## 扫描
def YaraScanFile (hash):
    fileUrl = configFileDir + "/" + hash

    with sqlLock:
        dbCur=dbCon.cursor()
    try:
        # 扫描文件
        matches = rules.match (fileUrl)
    except yara.Error as e:
        print(" \033[41m[E]\033[0m " + f"扫描 {fileUrl} 时出现错误: {e}")
        with sqlLock:
            dbCur.execute (f"UPDATE `file` SET `status` = 'Error' WHERE `hash` = {hash};")
            dbCur.execute(f"UPDATE `file` SET timestamp = '{int(time.time())}' WHERE hash = {hash};")
            dbCon.commit()
        return

    #生成报告
    report = []
    if len(matches)>0:
        print(" \033[43m[W]\033[0m " + f"文件 {fileUrl} 已被命中")
        for i in range(len(matches)):
            report=report+matches[i]+"/"
        #写入db
        with sqlLock:
            dbCur.execute(f"UPDATE `file` SET `matchs` = '{report}' WHERE `hash` = '{hash}';")
    with sqlLock:
        dbCur.execute (f"UPDATE `file` SET `status` = 'Done' WHERE `hash` = '{hash}';")
        dbCur.execute(f"UPDATE `file` SET `timestamp` = '{int(time.time())}' WHERE `hash` = '{hash}';")
        dbCur.execute(f"UPDATE `file` SET `rule_version` = '{ruleVersion}' WHERE `hash` = '{hash}';")
        dbCon.commit()



## 事件服务
def EventClock():
    print(" \033[42m[S]\033[0m " + "✅YaraAction计划任务已处于活跃状态!")
            


#规则编译
YaraRuleCompile()
#规则加载
YaraRuleLoad()

EventClock()
