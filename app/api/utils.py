def remove_private_attributes(data_dict: dict) -> dict:
    """
    Removes keys starting with an underscore from a dictionary,
    recursively handling nested dicts (and dicts inside lists/tuples).
    """

    def _clean(value):
        if isinstance(value, dict):
            return {
                k: _clean(v)
                for k, v in value.items()
                if not (isinstance(k, str) and k.startswith("_"))
            }
        if isinstance(value, list):
            return [_clean(item) for item in value]
        if isinstance(value, tuple):
            return tuple(_clean(item) for item in value)
        return value

    return _clean(data_dict)
