import yara
import os
import platform
import pymysql as sql

print ("\033[44m== Yara Engine API Project ==========\033[0m")
print ("\033[44mModule: YaraAction_Module\033[0m")
print ("\033[44mSystem: " + platform.platform() + "\033[0m")
print ("\033[44mPyVersion: " + platform.python_version() + "\033[0m")
print ("\033[44mCopyright © 2023 Shutdown & Kolomina, All rights reserved.\033[0m")
print ()


## 加载规则
def YaraRuleLoad(rulePath):
    for root, dirs, files in os.walk(rulePath):
        for file in files:
            if file.endswith('.yar'):
                filepath = os.path.join(root, file)
                try:
                    rules = yara.load(filepath)
                    print(" \033[42m[S]\033[0m " + f"已载入规则 {filepath}")
                except yara.Error as e:
                    print(" \033[41m[E]\033[0m " + f"在载入规则 {filepath} 时出现错误: {e}")
    return(rules)

## 扫描
def YaraMatch (id,scanPath, rule, dbCur):
    try:
        # 扫描可执行文件
        matches = rule.match(scanPath)
        print(" \033[47m[I]\033[0m " + f"已扫描 {scanPath}")
    except yara.Error as e:
        print(" \033[41m[E]\033[0m " + f"在使用 {scanPath} 扫描 {scanPath} 时出现错误: {e}")
    #生成报告
    report = []
    if len(matches)>0:
        print(" \033[43m[W]\033[0m " + f"文件 {scanPath} 已被命中")
        for i in range(len(matches)):
            report=report+matches[i]+"/"
        #写入db
        dbCur.execute(f"UPDATE `task` SET `matchs` = '{report}' WHERE `id` = `{str(id)}`;")
    dbCur.execute(f"UPDATE `task` SET `status` = 'Done' WHERE `task`.`id` = 13 ;")
    
dbCon = sql.connect(host="192.168.0.11",user="yara",password="7QhMQ7mBB7dGs2AY",database="yara")
YaraMatch(13,"/workspaces/python/YaraEngineAPI/ScanFile/60cfe344b06cc13231407f172c464701e3aa952588ec7d9f1396ac4ed0b631e3",YaraRuleLoad("/workspaces/python/YaraEngineAPI/RuleCompiled"),dbCon.cursor())