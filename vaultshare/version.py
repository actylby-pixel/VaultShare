"""版本常量。

线格式版本与程序版本互相独立：程序升级不改变协议，协议升级必须显式改这里的
数字并写清迁移路径。
"""

__version__ = "1.0.0"
PROTOCOL_VERSION = 1

STATE_FORMAT = "vaultshare-state"
KEYCONFIG_FORMAT = "vaultshare-keyconfig"
POLICY_FORMAT = "vaultshare-policy"
IDENTITY_FORMAT = "vaultshare-sender-identity"
REDEEM_FORMAT = "vaultshare-redeem"
ENVELOPE_FORMAT = "vaultshare-envelope"
RECEIPT_FORMAT = "vaultshare-receipt"
BROKER_IDENTITY_FORMAT = "vaultshare-broker-identity"
UPLOAD_KEY_FORMAT = "vaultshare-upload-key"
CONTAINER_MAGIC = b"VSPK"
# v2 在头部增加了“服务器地址提示”；v3 增加了发送方要求的核对标记。
# 读取端同时支持 v1（无地址）与 v2（无标记，按“必须核对”处理）。
CONTAINER_VERSION = 3
CONTAINER_VERSION_V2 = 2
CONTAINER_VERSION_V1 = 1
STREAM_SUITE_ID = 1
# 头部 flags 的第 0 位：发送方要求接收方核对发送方身份指纹。
CONTAINER_FLAG_REQUIRE_SENDER_FP = 0x01
