import yaml
import re
from typing import Dict, List, Any


class YAMLConfigManager:
    """
    A class to manage configuration data with support for variable expansion,
    multi-line strings, and serialization to/from YAML files.
    """

    def __init__(self):
        self.globals = {}
        self.items = []
        self.expanded_globals = {}

    def add_global(self, name: str, value: Any) -> None:
        """Add a global variable to the configuration."""
        self.globals[name] = value

    def add_item(self, env: Dict[str, Any], string: str) -> None:
        """Add an item to the configuration."""
        self.items.append({"env": env, "string": string})

    def _represent_multiline_str(self, dumper, data):
        """Custom YAML representer for multi-line strings."""
        if isinstance(data, str) and "\n" in data:
            return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)

    def save_to_yaml(self, file_path: str) -> None:
        """Save the configuration to a YAML file."""
        # Register the custom representer for multi-line strings
        yaml.add_representer(str, self._represent_multiline_str)

        complete_data = {"globals": self.globals, "items": self.items}

        with open(file_path, "w") as file:
            yaml.dump(complete_data, file, default_flow_style=False)

    def load_from_yaml(self, file_path: str) -> None:
        """Load the configuration from a YAML file."""
        with open(file_path, "r") as file:
            loaded_yaml = yaml.safe_load(file)

        self.globals = loaded_yaml.get("globals", {})
        self.items = loaded_yaml.get("items", [])

    def _expand_variables(self, data: Any, globals_dict: Dict[str, Any]) -> Any:
        """
        Recursively expand variables in the given data structure.
        """
        if isinstance(data, dict):
            return {k: self._expand_variables(v, globals_dict) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._expand_variables(item, globals_dict) for item in data]
        elif isinstance(data, str) and "${" in data:
            # Replace ${variable} with its actual value
            for var_name, var_value in globals_dict.items():
                placeholder = "${" + var_name + "}"
                if placeholder in data:
                    # If it's a full placeholder replacement
                    if data == placeholder:
                        return var_value
                    # If it's part of a string
                    data = data.replace(placeholder, str(var_value))
            return data
        else:
            return data

    def expand_globals(self) -> Dict[str, Any]:
        """
        Expand global variables that reference other globals.
        Returns the expanded globals dictionary.
        """
        globals_dict = self.globals.copy()
        expanded_globals = {}

        # Process until no more replacements are happening
        while True:
            changes_made = False
            for key, value in globals_dict.items():
                if isinstance(value, str) and "${" in value:
                    expanded_value = self._expand_variables(value, expanded_globals)
                    if expanded_value != value:
                        expanded_globals[key] = expanded_value
                        changes_made = True
                    elif key not in expanded_globals:
                        expanded_globals[key] = value
                elif key not in expanded_globals:
                    expanded_globals[key] = value

            # If we've processed all globals and no more changes were made, we're done
            if not changes_made or len(expanded_globals) == len(globals_dict):
                break

            # Update our working set with the expanded values
            globals_dict = expanded_globals.copy()

        self.expanded_globals = expanded_globals
        return expanded_globals

    def get_expanded_items(self) -> List[Dict[str, Any]]:
        """
        Expand variables in items using the expanded globals.
        Returns the expanded items list.
        """
        if not self.expanded_globals:
            self.expand_globals()

        return self._expand_variables(self.items, self.expanded_globals)


# Example usage
if __name__ == "__main__":
    # Create a new configuration
    '''
        config = YAMLConfigManager()

        # Add globals
        config.add_global("global_var1", "global_value1")
        config.add_global("global_var2", 42)
        config.add_global("global_var3", "${global_var1} combined with ${global_var2}")
        config.add_global("global_var4", "Multiple lines with ${global_var1}\nAnd ${global_var2} here")

        # Add items
        config.add_item(
            env={"name": "env1", "value": "${global_var1}"},
            string="This is a string using ${global_var3}\nIt spans multiple lines\nThird line here"
        )
        config.add_item(
            env={"name": "env2", "count": "${global_var2}"},
            string="""Another string with ${global_var4}
    This is the second line
    And this is the third line
    With proper indentation preserved"""
        )

        # Save to YAML
        config.save_to_yaml("config.yaml")
    '''

    # Create a new config and load from the saved YAML
    loaded_config = YAMLConfigManager()
    loaded_config.load_from_yaml("data.yaml")

    # Expand globals and items
    expanded_globals = loaded_config.expand_globals()
    expanded_items = loaded_config.get_expanded_items()

    # Print results
    print("Expanded globals:")
    for key, value in expanded_globals.items():
        print(f"{key}: {value}")

    print("\nExpanded items:")
    for item in expanded_items:
        print("\nEnvironment:", item["env"])
        print("String:")
        print(item["commands"])

