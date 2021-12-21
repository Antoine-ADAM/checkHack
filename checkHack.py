import re
import sys
import argparse
import os
import json

"""
@author: Antoine ADAM
@email: contact@antoineadam.fr
@date: 08/04/2020
@description: This program allows to scan all the python files of a directory to detect if they use native functions / variables or unauthorized imports.
"""

patern_rm_comment_A = re.compile("#.*?\n")
patern_rm_comment_B = re.compile("#.*?$")
def remove_comments_in_python(string: str) -> str:
    """
    Remove comments in python code.

    :param string: Python code.
    :return: Python code without comments.
    """
    # Remove comments in python code.
    string = re.sub(patern_rm_comment_A, "\n", string)
    string = re.sub(patern_rm_comment_B, "", string)
    return string




# Retrieve the dict of all the functions used in a python code
paterne_get_fn = re.compile("[a-zA-Z0-9_]+")
def get_functions_in_python(string: str) -> dict:
    """
    Retrieve the dict of all the functions used in a python code.

    :param string: Python code.
    :return: Dict of all the functions used in a python code.
    """

    # Retrieve the list of all the functions used in a python code.
    res = {}
    for e in re.finditer(paterne_get_fn, string):
        if e[0] not in res:
            res[e[0]]=string.count('\n', 0, e.start())
    return res

# Get the dict of all the imports of a python code
patern_get_import = re.compile("import[ ]+([a-zA-Z0-9_]+)")
def get_imports_in_python(string: str) -> dict:
    """
    Get the dict of all the imports of a python code.

    :param string: Python code.
    :return: Dict of all the imports of a python code.
    """

    # Get the dict of all the imports of a python code.
    res = {}
    for e in re.finditer(patern_get_import, string):
        res[e[1]]=string.count('\n', 0, e.start())
    return res

# Recursive list of files in a directory ending in .py
def get_files_in_dir(dir_path: str) -> list:
    """
    Recursive list of files in a directory ending in .py.

    :param dir_path: Directory path.
    :return: List of files in a directory ending in .py.
    """

    # Recursive list of files in a directory ending in .py
    res = []
    for e in os.listdir(dir_path):
        if os.path.isdir(dir_path+'/'+e):
            res += get_files_in_dir(dir_path+'/'+e)
        elif e.endswith('.py'):
            res.append(dir_path+'/'+e)
    return res

def generate_config_file(path_config: str):
    """
    Generate a config file.

    :param path_config: Path of the config file.
    """
    # Generate a config file.
    with open(path_config, 'w') as f:
        json.dump({"import_authorized": ["my_library"],
                   "prohibited_function": ["breakpoint", "compile", "eval", "exec", "exit", "locals", "globals", "help",
                                           "__loader__", "__file__"]}, f)

parser = argparse.ArgumentParser()
parser.add_argument("path_directory_analyse", help="Path of the directory to analyse.")
parser.add_argument("-config", help="Path of the config file.", default="config.json",metavar="path_config")
parser.add_argument("-genere_default_config", help="Generate a config file.", action="store_true")
args = parser.parse_args()

if args.genere_default_config:
    generate_config_file("config.json")
    exit(0)

try:
    with open(args.config) as f:
        config = json.load(f)
        if "import_authorized" in config and "prohibited_function" in config and isinstance(config["import_authorized"],list) and isinstance(config["prohibited_function"],list):
            import_authorized = config["import_authorized"]
            prohibited_function = config["prohibited_function"]
            for name in get_files_in_dir(args.path_directory_analyse):
                try:
                    with open(name) as f:
                        string = f.read()
                        string = remove_comments_in_python(string)
                        functions = get_functions_in_python(string)
                        imports = get_imports_in_python(string)
                        for e in imports:
                            if e not in import_authorized:
                                print(f"[{name}:{imports[e]}] Import not authorized: {e}")
                        for e in prohibited_function:
                            if e in functions:
                                print(f"[{name}:{functions[e]}] Function/Variable prohibited: {e}")
                except Exception as e:
                    print(f"Error in {name}: {e}")
        else:
            print("The config file is not valid.")
            sys.exit(1)
except FileNotFoundError:
    print("Config file not found.")
    sys.exit(1)
except json.decoder.JSONDecodeError:
    print("Config file is not a valid json file.")
    sys.exit(1)
except KeyError:
    print("Config file is not a valid json file.")
    sys.exit(1)
except Exception as e:
    print(e)
    sys.exit(1)