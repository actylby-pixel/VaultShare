"""跨进程文件锁。

Windows 用 ``msvcrt.locking``（非阻塞占 1 字节，轮询超时），POSIX 用
``fcntl.flock``。只支持本地磁盘；NFS 上的咨询锁不保证互斥，README 明确
不支持。

两个锁：
* ``locks/writer.lock``：服务进程启动时独占持有到退出，拒绝第二个写者；
* ``locks/state.lock``：每次状态事务获取，串行化「读 → 校验 → 更新 → 落盘」。
"""

from __future__ import annotations

import errno
import os
import time

__all__ = ["LockTimeout", "FileLock", "acquire_writer_lock"]


class LockTimeout(RuntimeError):
    pass


class FileLock:
    def __init__(self, path: str, timeout: float = 10.0, poll: float = 0.02):
        self.path = os.fspath(path)
        self.timeout = timeout
        self.poll = poll
        self._fd: int | None = None

    def _open(self) -> int:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        if os.name == "nt":
            # 文件至少 1 字节才能锁；多个进程写同一个 0 字节也安全（内容无意义）。
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            # msvcrt.locking 从**当前文件位置**开始锁：写入会把位置移到 1，
            # 不归零的话两个进程会锁到不同字节，互斥形同虚设。
            os.lseek(fd, 0, os.SEEK_SET)
        return fd

    def acquire(self) -> "FileLock":
        fd = self._open()
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._fd = fd
                return self
            except OSError as exc:
                retryable = exc.errno in {
                    errno.EACCES,
                    errno.EAGAIN,
                    errno.EDEADLK,
                    errno.EAGAIN if os.name == "nt" else errno.EAGAIN,
                } or (os.name == "nt" and exc.errno == 13)
                if not retryable or time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockTimeout(f"无法获取锁：{self.path}") from exc
                time.sleep(self.poll)

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            if os.name == "nt":
                import msvcrt

                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            os.close(fd)

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


def acquire_writer_lock(path: str) -> FileLock:
    """非等待：拿不到（第二个写者）立即失败。"""
    lock = FileLock(path, timeout=0.5)
    return lock.acquire()
