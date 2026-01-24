# SDDL Parser

A comprehensive Python parser for Windows Security Descriptor Definition Language (SDDL) strings, supporting File System, Registry, and Active Directory objects.

## Features

- **Multi-platform support**: Parse SDDL from File System, Registry, and Active Directory
- **Automatic type detection**: Intelligently detects the SDDL type based on structure
- **Rich output formats**: Export to JSON, plain text, or Rich-formatted tables
- **ACE merging**: Automatically merges duplicate ACEs with different inheritance scopes
- **Friendly names**: Resolves well-known SIDs to human-readable names
- **Advanced filtering**: Filter ACEs by sensitive trustees or sensitive rights
- **GUID resolution**: Resolves Active Directory object GUIDs to schema names

## Quick Start

```python
from sddl_parser import SDDLParser
from rich.console import Console

# Parse an SDDL string
sddl_string = "O:BAG:SYD:(A;;FA;;;BA)(A;;0x1200a9;;;WD)"
parser = SDDLParser()
parser.parse(sddl_string)

# Display as plain text
parser.dump()

# Export to JSON
json_output = parser.to_json()
print(json_output)

# Display as Rich table (requires Rich library)
console = Console()
parser.to_rich(console)
```

## Usage

### Basic Parsing

```python
from sddl_parser import SDDLParser

# Auto-detect SDDL type
parser = SDDLParser()
parser.parse(sddl_string)

# Or specify the type explicitly
parser = SDDLParser(sddl_type="File")
parser.parse(sddl_string)
```

### Output Methods

#### 1. Plain Text Output (`dump()`)

Prints a human-readable representation to the console:

```python
parser.dump()
```

**Output:**
```
OWNER:
  BUILTIN\Administrators (S-1-5-32-544)

GROUP:
  NT AUTHORITY\SYSTEM (S-1-5-18)

DACL:
  ACE #1
    Type: Access Allowed
    Applies to: This folder, subfolders and files
    Basic rights: Full Control
    Principal: BUILTIN\Administrators (S-1-5-32-544)
```

#### 2. JSON Export (`to_json()`)

Returns a JSON string representation:

```python
json_output = parser.to_json(indent=2)
```

**Output:**
```json
{
  "type": "File",
  "owner": {
    "sid": "S-1-5-32-544",
    "name": "BUILTIN\\Administrators"
  },
  "group": {
    "sid": "S-1-5-18",
    "name": "NT AUTHORITY\\SYSTEM"
  },
  "dacl": [
    {
      "type": "Access Allowed",
      "principal": {
        "sid": "S-1-5-32-544",
        "name": "BUILTIN\\Administrators"
      },
      "applies_to": "This folder, subfolders and files",
      "basic_rights": ["Full Control"],
      "advanced_rights": []
    }
  ],
  "sacl": []
}
```

#### 3. Rich Table Output (`to_rich()`)

Displays a formatted table using the Rich library:

```python
from rich.console import Console

console = Console()
parser.to_rich(
    console=console,
    title="OU=Domain Controllers,DC=serval,DC=int",
    sensitive_trustee=False,
    sensitive_rights=False,
    debug=False
)
```

**Parameters:**
- `console`: Rich Console object (required)
- `title`: Optional title displayed above the table
- `sensitive_trustee`: Filter to show only ACEs with sensitive trustees
- `sensitive_rights`: Filter to show only ACEs with sensitive rights
- `debug`: Show all ACEs regardless of filters

**Output:**
![WinSDDL rich table](.github/pictures/WinSDDL_rich_table.png)

## SDDL Types

The parser supports three types of SDDL strings:

### 1. File System

```python
sddl = "O:BAG:SYD:(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;WD)"
parser = SDDLParser(sddl_type="File")
parser.parse(sddl)
```

**Inheritance options:**
- This folder only
- This folder, subfolders and files
- This folder and subfolders
- This folder and files
- Subfolders and files only
- Subfolders only
- Files only

### 2. Registry

```python
sddl = "O:BAG:SYD:(A;CI;KA;;;BA)(A;CI;KR;;;WD)"
parser = SDDLParser(sddl_type="Registry")
parser.parse(sddl)
```

**Inheritance options:**
- This key only
- This key and subkeys
- Subkeys only

### 3. Active Directory

```python
sddl = "O:DAG:DAD:(OA;CI;CR;00299570-246d-11d0-a768-00aa006e0529;;BA)"
parser = SDDLParser(sddl_type="ActiveDirectory")
parser.parse(sddl)
```

**Features:**
- Object-specific ACEs with GUIDs
- Extended rights resolution
- Schema object and attribute resolution

## API Reference

### AccessControlEntry Class

Represents a single Access Control Entry.

**Attributes:**
- `ace_type`: Type of ACE (e.g., "Access Allowed", "Access Denied")
- `flags`: List of ACE flags
- `basic_rights`: List of basic rights (e.g., "Full Control", "Read")
- `advanced_rights`: List of advanced rights (e.g., "Read Data", "Write Data")
- `trustee`: SecurityIdentifier object for the principal
- `applies_to_this`: Boolean indicating if ACE applies to this object
- `applies_to_subfolders`: Boolean for subfolder inheritance
- `applies_to_files`: Boolean for file inheritance
- `object_type`: GUID or name for object-specific ACEs (Active Directory)
- `inherited_object_type`: GUID or name for inherited object type

### SecurityIdentifier Class

Represents a Windows Security Identifier.

**Attributes:**
- `sid`: The SID string (e.g., "S-1-5-32-544")
- `name`: Resolved friendly name (e.g., "BUILTIN\\Administrators")

## Well-Known SIDs

The parser automatically resolves well-known SIDs to friendly names:

| SID | Name |
|-----|------|
| S-1-5-32-544 | BUILTIN\Administrators |
| S-1-5-32-545 | BUILTIN\Users |
| S-1-5-18 | NT AUTHORITY\SYSTEM |
| S-1-1-0 | Everyone |
| S-1-5-11 | Authenticated Users |
| S-1-5-7 | Anonymous Logon |

And many more...

## Permissions Mapping

### File System Rights

**Basic Rights:**
- Full Control
- Modify
- Read & Execute
- Read
- Write

**Advanced Rights:**
- Traverse Folder / Execute File
- List Folder / Read Data
- Read Attributes
- Read Extended Attributes
- Create Files / Write Data
- Create Folders / Append Data
- Write Attributes
- Write Extended Attributes
- Delete Subfolders and Files
- Delete
- Read Permissions
- Change Permissions
- Take Ownership

### Registry Rights

**Basic Rights:**
- Full Control
- Read
- Special Permissions

**Advanced Rights:**
- Query Value
- Set Value
- Create Subkey
- Enumerate Subkeys
- Notify
- Create Link
- Delete
- Write DAC
- Write Owner
- Read Control