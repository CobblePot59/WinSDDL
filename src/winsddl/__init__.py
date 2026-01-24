"""
SDDL Parser for Windows Security Descriptors
Supports File System, Registry, and Active Directory objects
"""

from .constants import *
from dataclasses import dataclass, field
import re
import json


DOMAIN_SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+-(\d+)$")

@dataclass
class SecurityIdentifier:
    """Represents a Windows Security Identifier (SID)"""
    sid: str
    name: str = field(init=False)

    def __post_init__(self):
        """Resolve SID to friendly name using well-known SIDs mapping"""
        if self.sid in WELL_KNOWN_SIDS:
            self.name = WELL_KNOWN_SIDS[self.sid]
        elif (m := DOMAIN_SID_RE.search(self.sid)):
            self.name = WELL_KNOWN_SIDS.get(f"domain-{m.group(1)}", self.sid)
        else:
            self.name = self.sid

    def __str__(self):
        return f"{self.name} ({self.sid})" if self.name != self.sid else self.sid


@dataclass
class AccessControlEntry:
    """Represents a single Access Control Entry (ACE)"""
    ace_type: str
    flags: list
    basic_rights: list
    advanced_rights: list
    trustee: SecurityIdentifier
    applies_to_this: bool
    applies_to_subfolders: bool
    applies_to_files: bool
    object_type: str = None
    inherited_object_type: str = None


class SDDLParser:  
    # Standard ACE format: (type;flags;rights;;;sid)
    ACE_STANDARD_RE = re.compile(r'\(([AD]);([^;]*);([^;]+);;;(.+?)\)')
    
    # Object ACE format for Active Directory: (type;flags;rights;object_guid;inherited_object_guid;sid)
    ACE_OBJECT_RE = re.compile(r'\(([OA|OD|OU]+);([^;]*);([^;]+);([^;]*);([^;]*);(.+?)\)')

    def __init__(self, sddl_type="auto"):
        self.sddl_type = sddl_type
        self.owner = None
        self.group = None
        self.dacl = []
        self.sacl = []
        self.dacl_flags = None
        self.sacl_flags = None

    def detect_type(self, sddl):
        if re.search(r'\(O[AU];', sddl):
            return "ActiveDirectory"

        if re.search(r'F[ARWX]|OI', sddl):
            return "File"

        if re.search(r'K[ARWX]', sddl):
            return "Registry"
        
        return "Unknown"

    def decode_flags(self, raw_flags):
        return [ACE_FLAGS[flag] for flag in re.findall(r'..', raw_flags) if flag in ACE_FLAGS]

    def mask_to_advanced_rights(self, mask):
        if self.sddl_type == "ActiveDirectory":
            rights_map = ADOBJECT_ADVANCED_RIGHTS
        elif self.sddl_type == "File":
            rights_map = FILE_ADVANCED_RIGHTS
        else:
            rights_map = REGISTRY_ADVANCED_RIGHTS
        
        return [name for bit, name in rights_map.items() if (mask & bit) == bit]

    def reduce_to_basic_rights(self, advanced_rights, basic_rights_map):
        if not advanced_rights:
            return []
        
        # Create reverse mapping from right names to masks
        name_to_mask = {name: mask for mask, name in basic_rights_map.items()}
        
        # Find valid mappings
        valid_rights = [(name_to_mask[right], right) 
                       for right in advanced_rights 
                       if right in name_to_mask]
        
        if not valid_rights:
            return advanced_rights
        
        # Return the highest-level basic right
        return [max(valid_rights, key=lambda x: x[0])[1]]

    def decode_rights(self, rights_string):
        mask = 0

        # Select appropriate mappings based on SDDL type
        if self.sddl_type == "ActiveDirectory":
            short_codes_map = {}
            basic_rights_map = ADOBJECT_BASIC_RIGHTS
        elif self.sddl_type == "File":
            short_codes_map = FILE_RIGHTS_MAP
            basic_rights_map = FILE_BASIC_RIGHTS
        else:
            short_codes_map = REGISTRY_RIGHTS_MAP
            basic_rights_map = REGISTRY_BASIC_RIGHTS

        # Check if rights string is a known short code
        if rights_string in short_codes_map:
            mask = short_codes_map[rights_string]
        
        # Check if rights string is hexadecimal
        elif rights_string.startswith("0x"):
            try:
                mask = int(rights_string, 16)
            except ValueError:
                return [], [rights_string]
        
        # Parse as two-character right codes
        else:
            mask = 0
            for code in re.findall(r'..', rights_string):
                if code in ACE_RIGHTS_MAP:
                    mask |= ACE_RIGHTS_MAP[code]

        # Check if mask matches a basic right
        if mask in basic_rights_map:
            return [basic_rights_map[mask]], []

        # Convert to advanced rights
        advanced_rights = self.mask_to_advanced_rights(mask)
        return [], advanced_rights

    def resolve_guid(self, guid):
        if not guid:
            return None

        guid_lower = guid.lower()

        if guid_lower in SCHEMA_OBJECTS:
            return SCHEMA_OBJECTS[guid_lower]

        if guid_lower in SCHEMA_ATTRIBUTES:
            return SCHEMA_ATTRIBUTES[guid_lower]


        if guid_lower in EXTENDED_RIGHTS:
            return EXTENDED_RIGHTS[guid_lower]
        
        return guid

    def parse_ace(self, ace_string):
        # Try parsing as Object ACE (Active Directory format)
        match = self.ACE_OBJECT_RE.match(ace_string)
        object_guid = None
        inherited_object_guid = None
        
        if match:
            ace_type, flags, rights, obj_guid, inherit_obj_guid, sid = match.groups()
            object_guid = self.resolve_guid(obj_guid) if obj_guid else None
            inherited_object_guid = self.resolve_guid(inherit_obj_guid) if inherit_obj_guid else None
        else:
            # Try parsing as standard ACE
            match = self.ACE_STANDARD_RE.match(ace_string)
            if not match:
                return None
            ace_type, flags, rights, sid = match.groups()

        # Decode flags
        decoded_flags = self.decode_flags(flags)

        # Decode rights
        basic_rights = []
        advanced_rights = []

        if rights.startswith("0x"):
            try:
                mask = int(rights, 16)

                # Check for generic rights mappings
                if self.sddl_type == "File" and mask in FILE_GENERIC_TO_BASIC:
                    basic_rights = [FILE_GENERIC_TO_BASIC[mask]]
                elif self.sddl_type == "ActiveDirectory" and mask in ADOBJECT_GENERIC_TO_BASIC:
                    basic_rights = [ADOBJECT_GENERIC_TO_BASIC[mask]]
                else:
                    basic_rights, advanced_rights = self.decode_rights(rights)

            except ValueError:
                advanced_rights = [rights]
        else:
            basic_rights, advanced_rights = self.decode_rights(rights)

        # Reduce advanced rights to basic rights if possible
        if self.sddl_type == "ActiveDirectory":
            basic_rights_map = ADOBJECT_BASIC_RIGHTS
        elif self.sddl_type == "File":
            basic_rights_map = FILE_BASIC_RIGHTS
        else:
            basic_rights_map = REGISTRY_BASIC_RIGHTS
            
        basic_rights = self.reduce_to_basic_rights(basic_rights, basic_rights_map)

        # If we have basic rights, clear advanced rights
        if basic_rights:
            advanced_rights = []

        # Determine inheritance scope
        has_container_inherit = "Container Inherit" in decoded_flags
        has_object_inherit = "Object Inherit" in decoded_flags
        has_inherit_only = "Inherit Only" in decoded_flags

        applies_to_this = not has_inherit_only
        applies_to_subfolders = has_container_inherit
        applies_to_files = has_object_inherit

        return AccessControlEntry(
            ace_type=ACE_TYPES.get(ace_type, ace_type),
            flags=decoded_flags,
            basic_rights=basic_rights,
            advanced_rights=advanced_rights,
            trustee=SecurityIdentifier(sid),
            applies_to_this=applies_to_this,
            applies_to_subfolders=applies_to_subfolders,
            applies_to_files=applies_to_files,
            object_type=object_guid,
            inherited_object_type=inherited_object_guid,
        )

    def merge_aces(self, aces):
        merged = {}
        
        for ace in aces:
            # Create unique key for this ACE (excluding inheritance scope)
            key = (
                ace.trustee.sid,
                ace.ace_type,
                tuple(ace.basic_rights),
                tuple(ace.advanced_rights),
                ace.object_type,
                ace.inherited_object_type,
            )
            
            if key not in merged:
                merged[key] = ace
                continue
            
            # Merge inheritance scopes
            existing = merged[key]
            existing.applies_to_this |= ace.applies_to_this
            existing.applies_to_subfolders |= ace.applies_to_subfolders
            existing.applies_to_files |= ace.applies_to_files
        
        return list(merged.values())

    def get_inheritance_description(self, ace):
        if self.sddl_type == "ActiveDirectory":
            # Active Directory inheritance descriptions
            if ace.inherited_object_type:
                scope = f"Descendant {ace.inherited_object_type} objects"
            else:
                scope = "This object and all descendant objects"
            
            if not ace.applies_to_this and ace.applies_to_subfolders:
                return "All descendant objects"
            elif ace.applies_to_this and ace.applies_to_subfolders:
                return scope
            else:
                return "This object only"
        
        if self.sddl_type == "Registry":
            # Registry inheritance descriptions
            if ace.applies_to_this and ace.applies_to_subfolders:
                return "This key and subkeys"
            elif ace.applies_to_subfolders:
                return "Subkeys only"
            else:
                return "This key only"

        # File system inheritance descriptions
        inheritance_key = (
            ace.applies_to_this,
            ace.applies_to_subfolders,
            ace.applies_to_files,
        )

        return FILE_INHERITANCE_MAP.get(inheritance_key, "This folder only")

    def parse_acl(self, sddl, tag):
        # Extract ACL section using regex
        match = re.search(fr'{tag}:([^\s]*?)(?:[DS]:|$)', sddl)
        if not match:
            return [], None

        raw_acl = match.group(1)
        
        # Extract ACL flags if present
        flags_match = re.match(r'^([A-Z]+)', raw_acl)
        acl_flags = flags_match.group(1) if flags_match else None
        raw_acl = raw_acl[len(acl_flags):] if acl_flags else raw_acl

        # Parse individual ACEs
        ace_strings = re.findall(r'\([^)]+\)', raw_acl)
        aces = [ace for ace in (self.parse_ace(ace_str) for ace_str in ace_strings) if ace]
        
        return aces, acl_flags

    def parse_sid(self, sddl, tag):
        match = re.search(fr'{tag}:(S-[\d-]+)', sddl)
        return SecurityIdentifier(match.group(1)) if match else None

    def parse(self, sddl):
        # Auto-detect SDDL type if needed
        if self.sddl_type == "auto":
            self.sddl_type = self.detect_type(sddl)

        # Parse Owner and Group
        self.owner = self.parse_sid(sddl, "O")
        self.group = self.parse_sid(sddl, "G")

        # Parse DACL and SACL
        self.dacl, self.dacl_flags = self.parse_acl(sddl, "D")
        self.sacl, self.sacl_flags = self.parse_acl(sddl, "S")

        # Merge duplicate ACEs
        self.dacl = self.merge_aces(self.dacl)
        self.sacl = self.merge_aces(self.sacl)

        return self

    def dump(self):
        """Print human-readable representation of security descriptor to console."""
        if self.owner:
            print("\nOWNER:")
            print(f"  {self.owner}")

        if self.group:
            print("\nGROUP:")
            print(f"  {self.group}")

        if self.dacl:
            print("\nDACL:")
            if self.dacl_flags:
                print(f"  Flags: {self.dacl_flags}")
            
            for i, ace in enumerate(self.dacl, 1):
                print(f"\n  ACE #{i}")
                print(f"    Type: {ace.ace_type}")
                print(f"    Applies to: {self.get_inheritance_description(ace)}")
                
                if ace.object_type:
                    print(f"    Object type: {ace.object_type}")
                if ace.inherited_object_type:
                    print(f"    Inherited object type: {ace.inherited_object_type}")
                
                if ace.basic_rights:
                    print(f"    Basic rights: {', '.join(ace.basic_rights)}")
                if ace.advanced_rights:
                    print(f"    Advanced rights: {', '.join(ace.advanced_rights)}")
                
                print(f"    Principal: {ace.trustee}")

        if self.sacl:
            print("\nSACL:")
            if self.sacl_flags:
                print(f"  Flags: {self.sacl_flags}")
            
            for i, ace in enumerate(self.sacl, 1):
                print(f"\n  ACE #{i}")
                print(f"    Type: {ace.ace_type}")
                print(f"    Applies to: {self.get_inheritance_description(ace)}")
                
                if ace.object_type:
                    print(f"    Object type: {ace.object_type}")
                if ace.inherited_object_type:
                    print(f"    Inherited object type: {ace.inherited_object_type}")
                    
                print(f"    Principal: {ace.trustee}")

    def ace_to_dict(self, ace):
        if self.sddl_type == "ActiveDirectory" and ace.object_type:
            basic_rights = [f"{right} ({ace.object_type})" for right in ace.basic_rights]
            advanced_rights = [f"{right} ({ace.object_type})" for right in ace.advanced_rights]
        else:
            basic_rights = ace.basic_rights
            advanced_rights = ace.advanced_rights
        
        result = {
            "type": ace.ace_type,
            "principal": {
                "sid": ace.trustee.sid,
                "name": ace.trustee.name,
            },
            "applies_to": self.get_inheritance_description(ace),
            "basic_rights": basic_rights,
            "advanced_rights": advanced_rights,
        }
        
        if ace.object_type:
            result["object_type"] = ace.object_type
        if ace.inherited_object_type:
            result["inherited_object_type"] = ace.inherited_object_type
            
        return result
    
    def to_json(self, indent=2):
        """Convert security descriptor to JSON string."""
        data = {
            "type": self.sddl_type,
            "owner": (
                {"sid": self.owner.sid, "name": self.owner.name}
                if self.owner else None
            ),
            "group": (
                {"sid": self.group.sid, "name": self.group.name}
                if self.group else None
            ),
            "dacl": [self.ace_to_dict(ace) for ace in self.dacl],
            "sacl": [self.ace_to_dict(ace) for ace in self.sacl],
        }

        return json.dumps(data, indent=indent)
    
    def to_rich(self, console, title=None, sensitive_trustee=False, sensitive_rights=False, debug=False):
        """Display security descriptor as a Rich table."""
        from rich.table import Table
        
        # Display title if provided
        if title:
            console.print(f"\n[bold yellow]{title}[/bold yellow]")
        
        # Check if DACL exists
        if not self.dacl:
            console.print("[dim]No DACL present[/dim]")
            return
        
        # Initialize table structure
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("AceType", style="cyan", no_wrap=True)
        table.add_column("Principal", style="green")
        table.add_column("Rights", style="white")
        table.add_column("Applies to", style="dim")
        
        # Determine if this is an Active Directory SDDL
        is_active_directory = self.sddl_type == "ActiveDirectory"
        
        # Track if any ACEs were displayed
        has_displayed_aces = False
        
        # Process each Access Control Entry
        for ace in self.dacl:
            # Extract ACE components
            ace_type = ace.ace_type
            principal_name = ace.trustee.name
            
            # Get rights (basic or advanced)
            if is_active_directory and ace.object_type:
                rights = [f"{right} ({ace.object_type})" for right in (ace.basic_rights or ace.advanced_rights)]
            else:
                rights = ace.basic_rights or ace.advanced_rights or []
            
            # Get scope of application
            applies_to = self.get_inheritance_description(ace)
            
            # Determine if this trustee is sensitive
            is_sensitive_trustee = False
            if sensitive_trustee:
                is_sensitive_trustee = any(trustee in principal_name.lower() for trustee in SENSITIVE_TRUSTEES)
            
            # Identify sensitive rights
            sensitive_rights_found = []
            if sensitive_rights:
                sensitive_rights_found = [right for right in rights if right in SENSITIVE_FILE_RIGHTS]
            
            # Apply filters (skip ACE if filters don't match and not in debug mode)
            if not debug:
                if sensitive_trustee and not is_sensitive_trustee:
                    continue
                if sensitive_rights and not sensitive_rights_found:
                    continue
            
            # Format display name (highlight sensitive trustees)
            if is_sensitive_trustee:
                principal_name = f"[bold red]{principal_name}[/bold red]"
            
            # Format rights display (highlight sensitive rights)
            if sensitive_rights and rights:
                rights_display = "\n".join(
                    f"[bold red]{right}[/bold red]" if right in sensitive_rights_found else right
                    for right in rights
                )
            else:
                rights_display = "\n".join(rights) if rights else "-"
            
            # Add row to table
            table.add_row(ace_type, principal_name, rights_display, applies_to)
            has_displayed_aces = True
        
        # Handle case where no ACEs matched filters
        if not has_displayed_aces:
            console.print("[dim italic]No rights granted to sensitive trustees[/dim italic]")
            
            # In debug mode, show all ACEs regardless of filters
            if debug:
                for ace in self.dacl:
                    ace_type = ace.ace_type
                    principal_name = ace.trustee.name
                    
                    if is_active_directory and ace.object_type:
                        rights = [f"{right} ({ace.object_type})" for right in (ace.basic_rights or ace.advanced_rights)]
                    else:
                        rights = ace.basic_rights or ace.advanced_rights or []
                    
                    applies_to = self.get_inheritance_description(ace)
                    rights_display = "\n".join(rights) if rights else "-"
                    table.add_row(ace_type, principal_name, rights_display, applies_to)
            else:
                return
        
        # Display the table
        console.print(table)
        
        # Display owner and group information
        owner_name = self.owner.name if self.owner else "-"
        group_name = self.group.name if self.group else "-"
        
        console.print(
            f"[bold cyan]Owner:[/bold cyan] {owner_name}, "
            f"[bold cyan]Group:[/bold cyan] {group_name}"
        )