import os
import xml.etree.ElementTree as ET
import sqlite3


def truthy(value):
    return str(value).lower() in {"1", "true", "yes"}


def api_export_names(api):
    api_name = api.attrib.get("Name", "")
    if not api_name:
        return []

    if not truthy(api.attrib.get("BothCharset", "False")):
        return [api_name]

    suffix_a = api.attrib.get("SuffixA", "A")
    suffix_w = api.attrib.get("SuffixW", "W")
    names = [api_name + suffix_a, api_name + suffix_w]

    # Some dictionary entries use BothCharset for a pair where the ANSI export
    # is the undecorated base name. Keep the base name too when it is distinct.
    if api_name not in names:
        names.insert(0, api_name)

    return names

def parse_xml_files(dictionary_path):
    api_defs = {}
    
    # Recursively search all directories in API Dictionary
    for root, _, files in os.walk(dictionary_path):
        for file in files:
            if not file.endswith(".xml"):
                continue
            
            file_path = os.path.join(root, file)
            try:
                tree = ET.parse(file_path)
                xml_root = tree.getroot()
                
                # Runtime hooks can only target exported module APIs. Interface
                # definitions are still useful documentation, but they do not
                # map directly to a DLL export for MinHook.
                for module in xml_root.findall(".//Module"):
                    module_name = module.attrib.get("Name", "")
                    calling_convention = module.attrib.get("CallingConvention", "")
                    error_func = module.attrib.get("ErrorFunc", "")
                    
                    for api in module.findall("Api"):
                        ret_elem = api.find("Return")
                        return_type = ret_elem.attrib.get("Type", "void") if ret_elem is not None else "void"

                        params = []
                        for idx, param in enumerate(api.findall("Param")):
                            p_name = param.attrib.get("Name", f"param{idx}")
                            p_type = param.attrib.get("Type", "void*")
                            length_param = param.attrib.get("Length", "")
                            post_length_param = param.attrib.get("PostLength", "")
                            params.append({
                                "name": p_name,
                                "type": p_type,
                                "position": idx,
                                "length_param": length_param,
                                "post_length_param": post_length_param
                            })

                        ordinal = api.attrib.get("Ordinal", "")
                        category = ""

                        for candidate in api_export_names(api):
                            key = (module_name.lower(), candidate)
                            if key in api_defs:
                                continue

                            api_defs[key] = {
                                "name": candidate,
                                "module": module_name,
                                "return_type": return_type,
                                "calling_convention": calling_convention,
                                "error_func": error_func,
                                "ordinal": ordinal,
                                "category": category,
                                "params": params
                            }
            except Exception as e:
                # Silently ignore format errors in some header files
                pass
                
    return api_defs

def build_database(api_defs, db_path):
    # Ensure directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    if os.path.exists(db_path):
        os.remove(db_path)
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
    CREATE TABLE apis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        module TEXT,
        return_type TEXT,
        calling_convention TEXT,
        error_func TEXT,
        ordinal_name TEXT,
        category TEXT,
        UNIQUE(module, name)
    )
    """)
    
    cursor.execute("""
    CREATE TABLE parameters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_id INTEGER,
        name TEXT,
        type TEXT,
        position INTEGER,
        length_param TEXT,
        post_length_param TEXT,
        FOREIGN KEY(api_id) REFERENCES apis(id)
    )
    """)
    
    for _, info in sorted(api_defs.items(), key=lambda item: (item[1]["module"].lower(), item[1]["name"].lower())):
        cursor.execute(
            "INSERT INTO apis (name, module, return_type, calling_convention, error_func, ordinal_name, category) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                info["name"],
                info["module"],
                info["return_type"],
                info["calling_convention"],
                info["error_func"],
                info["ordinal"],
                info["category"],
            )
        )
        api_id = cursor.lastrowid
        
        for param in info["params"]:
            cursor.execute(
                "INSERT INTO parameters (api_id, name, type, position, length_param, post_length_param) VALUES (?, ?, ?, ?, ?, ?)",
                (api_id, param["name"], param["type"], param["position"], param["length_param"], param["post_length_param"])
            )
            
    conn.commit()
    conn.close()
    print(f"Successfully generated database with {len(api_defs)} APIs at: {db_path}")

if __name__ == "__main__":
    dict_dir = r"c:\Work\RESEARCH_AREA\Inspecthor\API Dictionary"
    output_db = r"c:\Work\RESEARCH_AREA\Inspecthor\bin\signatures.db"
    
    print("Parsing API Dictionaries...")
    definitions = parse_xml_files(dict_dir)
    print(f"Found {len(definitions)} dictionary APIs.")
    build_database(definitions, output_db)
