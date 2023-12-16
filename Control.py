import yara
import os


## 预编译规则
def compile_rules():
    # Set rules directory HERE
    directory = "./RulesOrigin"

    rule_files = {}
    for index, filename in enumerate(os.listdir(directory)):
        rule_path = os.path.join(directory, filename)
        rule_files[f"rule{index}"] = rule_path
    compiled_rules = yara.compile(filepaths=rule_files)
    return compiled_rules
