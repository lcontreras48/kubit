from importlib.metadata import PackageNotFoundError, version


def application_version() -> str:
    """Return the version embedded in the installed Kubit wheel."""
    try:
        return version("kubit")
    except PackageNotFoundError:
        return "development"
