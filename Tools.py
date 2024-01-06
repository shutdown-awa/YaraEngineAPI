import os
import yara
import platform

print ("\033[44m== Yara Engine API Project ==========\033[0m")
print ("\033[44mModule: Control_Module\033[0m")
print ("\033[44mSystem: " + platform.platform() + "\033[0m")
print ("\033[44mPyVersion: " + platform.python_version() + "\033[0m")
print ("\033[44mYaraVersion: " + str(yara.__version__) + "\033[0m")
print ("\033[44mCopyright © 2023 Shutdown & Kolomina, All rights reserved.\033[0m")
print ()


## 规则预编译




#ruleOriginPath = input("规则输入目录[./RuleOrigin]: ")
#if ruleOriginPath == "":
#    ruleOriginPath = "./RuleOrigin"
#ruleCompiledPath = input("规则输出目录[./RuleCompiled]: ")
#if ruleCompiledPath == "":
#    ruleCompiledPath = "./RuleOrigin"
#compile_yara_rules(ruleOriginPath, ruleCompiledPath)
