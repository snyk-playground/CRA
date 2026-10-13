"""Exception hierarchy mapped to process exit codes.

The entry point catches SnykCraSbomVexError (or a subclass) at the top
level and exits with the matching exit_code, per the requirement to
exit non-zero on any unrecoverable error. Subclasses below correspond to
the specific unrecoverable-error cases called out; more may be added
as discovery/sbom/vex modules are implemented.
"""


class SnykCraSbomVexError(Exception):
    """Base class for every error this tool raises deliberately."""

    exit_code = 1


class ConfigError(SnykCraSbomVexError):
    """Invalid or missing configuration (e.g. no API token available)."""

    exit_code = 2


class AuthenticationError(SnykCraSbomVexError):
    """The Snyk API rejected the supplied token."""

    exit_code = 3


class SourceNotFoundError(SnykCraSbomVexError):
    """A named --org/--target/--asset/--project/--group/--tag source does not exist."""

    exit_code = 4


class NoProjectsDiscoveredError(SnykCraSbomVexError):
    """The union of all resolved sources contained zero in-scope projects."""

    exit_code = 5


class ProjectFetchError(SnykCraSbomVexError):
    """A single project's SBOM/issues fetch failed and --fail-fast is set."""

    exit_code = 6


class OutputWriteError(SnykCraSbomVexError):
    """An output file (or its parent directory) could not be written."""

    exit_code = 7
