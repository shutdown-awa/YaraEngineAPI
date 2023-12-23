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
def compile_yara_rules(src_dir, dest_dir):
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



ruleOriginPath = input("规则输入目录[./RuleOrigin]: ")
if ruleOriginPath == "":
    ruleOriginPath = "./RuleOrigin"
ruleCompiledPath = input("规则输出目录[./RuleCompiled]: ")
if ruleCompiledPath == "":
    ruleCompiledPath = "./RuleOrigin"
compile_yara_rules(ruleOriginPath, ruleCompiledPath)