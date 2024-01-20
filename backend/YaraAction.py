import yara
import os
import platform
import pymysql as sql
import time
import threading
import configparser

print ("\033[44m== Yara Engine API Project ==========\033[0m")
print ("\033[44mModule: YaraAction_Module\033[0m")
print ("\033[44mSystem: " + platform.platform() + "\033[0m")
print ("\033[44mPyVersion: " + platform.python_version() + "\033[0m")
print ("\033[YaraVersion: " + str(yara.__version__) + "\033[0m")
print ("\033[44mCopyright © 2023 Shutdown & Kolomina, All rights reserved.\033[0m")
print ()


# 读取配置
config = configparser.read("./setting.ini")

configRule = config.items("rule")
configRule = dict(configRule)
yaraRuleOriginDir = configRule["src_dir"] #yara规则未编译目录
yaraRuleCompileDir = configRule["dest_dir"] #yara规则编译目录

configSql = config.items("sql")
configSql = dict(configSql)
dbHost = configSql["host"] #数据库服务器
dbUsr = configSql["user"] #数据库用户
dbPwd = configSql["password"] #数据库密码
dbName = configSql["name"] #数据库名字



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


## 规则编译器
def YaraRuleCompile(src_dir, dest_dir):
    print(" \033[47m[I]\033[0m " + "现在开始预编译规则😋")

    # 获取版本信息
    versionInfoAtSrc = os.read(os.open(src_dir+"/version"))
    versionInfoAtDst = os.read(os.open(dest_dir+"/version"))
    if versionInfoAtSrc == versionInfoAtDst:
        return
    
    print("发现规则更新🥳！重新编译～～～～～～")
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
                print(" \033[42m[S]\033[0m " + "预编译已完成😋")
            except yara.Error as e:
                print(" \033[41m[E]\033[0m " + f"在编译规则 {file_path} 时出现错误: {e}")
                continue


## 加载规则
def YaraRuleLoad(rulePath):
    for root, dirs, files in os.walk(rulePath):
        for file in files:
            if file.endswith('.yar'):
                filepath = os.path.join(root, file)
                try:
                    rules = yara.load(filepath)
                except yara.Error as e:
                    print(" \033[41m[E]\033[0m " + f"在载入规则 {filepath} 时出现错误: {e}")
    return(rules)

## 扫描
def YaraMatch (id,filePath):
    with sqlLock:
        dbCur=dbCon.cursor()
    try:
        # 扫描文件
        matches = rule.match(filePath)
    except yara.Error as e:
        print(" \033[41m[E]\033[0m " + f"在使用 {filePath} 扫描 {filePath} 时出现错误: {e}")
        with sqlLock:
            dbCur.execute (f"UPDATE `task` SET `status` = 'ERROR' WHERE `id` = {id};")
            dbCur.execute(f"UPDATE task SET endTime = '{int(time.time())}' WHERE id = {id};")
            dbCon.commit()
        return

    #生成报告
    report = []
    if len(matches)>0:
        print(" \033[43m[W]\033[0m " + f"文件 {filePath} 已被命中")
        for i in range(len(matches)):
            report=report+matches[i]+"/"
        #写入db
        with sqlLock:
            dbCur.execute(f"UPDATE `task` SET `matchs` = '{report}' WHERE `id` = {id};")
    with sqlLock:
        dbCur.execute (f"UPDATE `task` SET `status` = 'Done' WHERE `id` = {id};")
        dbCur.execute(f"UPDATE task SET endTime = '{int(time.time())}' WHERE id = {id};")
        dbCon.commit()


## 事件服务
        def EventClock():
            print(" \033[42m[S]\033[0m " + "✅Controller计划任务已处于活跃状态!")
            
