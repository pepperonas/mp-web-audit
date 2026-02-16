"""Exception-Hierarchie fuer mp-web-audit."""


class WebAuditError(Exception):
    """Basis-Exception fuer alle Web-Audit-Fehler."""


class ScanError(WebAuditError):
    """Fehler waehrend eines Scans."""


class ConfigError(WebAuditError):
    """Fehler in der Konfiguration."""


class AuthorizationError(WebAuditError):
    """Nutzer hat die Autorisierung verweigert."""


class ExternalToolError(WebAuditError):
    """Externes Tool (nmap, feroxbuster, sslyze) nicht verfuegbar oder fehlgeschlagen."""

    def __init__(self, tool: str, message: str) -> None:
        self.tool = tool
        super().__init__(f"{tool}: {message}")


class HttpClientError(WebAuditError):
    """Fehler beim HTTP-Request."""
