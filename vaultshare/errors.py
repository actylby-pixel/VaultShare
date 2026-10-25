"""统一的异常类型。

路由层只把这些异常映射成 HTTP 状态码；任何未预期异常仍然走 500，不能悄悄
降级成"拒绝"——两者在审计里必须可区分。
"""

from __future__ import annotations


class VaultShareError(Exception):
    """所有业务异常的基类。"""

    status = 400
    code = "error"

    def __init__(self, message: str = "", *, code: str | None = None):
        super().__init__(message or self.code)
        self.message = message or self.code
        if code is not None:
            self.code = code


class ValidationError(VaultShareError):
    status = 400
    code = "invalid"


class NotAuthenticated(VaultShareError):
    status = 401
    code = "unauthenticated"


class Forbidden(VaultShareError):
    status = 403
    code = "forbidden"


class NotFound(VaultShareError):
    status = 404
    code = "not_found"


class Conflict(VaultShareError):
    status = 409
    code = "conflict"


class Gone(VaultShareError):
    status = 410
    code = "gone"


class Unavailable(VaultShareError):
    status = 503
    code = "unavailable"


class CorruptState(VaultShareError):
    status = 503
    code = "state_corrupt"


class BrokerError(VaultShareError):
    status = 502
    code = "broker_error"


class IpcError(BrokerError):
    code = "ipc_error"
