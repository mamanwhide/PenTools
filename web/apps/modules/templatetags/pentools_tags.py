"""Custom template filters for PenTools."""
from django import template

register = template.Library()


@register.filter(name="replace")
def replace_filter(value, arg):
    """Replace a character in a string with a space.

    Usage: {{ value|replace:"_"|title }}
    Replaces every occurrence of arg with a single space.

    Example: "scan_complete"|replace:"_" -> "scan complete"
    """
    return str(value).replace(str(arg), " ")


@register.filter(name="get_item")
def get_item(mapping, key):
    """Retrieve a value from a dict by key in a template.

    Usage: {{ my_dict|get_item:some_variable }}
    """
    try:
        return mapping[key]
    except (KeyError, TypeError):
        return None
