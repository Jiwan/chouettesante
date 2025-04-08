pub const RECORD_MAGIC_NUMBER: u16 = 0xcc51;
pub const RECORD_PACKET_MAX_SIZE: usize = 0x588;
pub const RECORD_HEADER_SIZE: usize = 0xc;

// Extracted from iotcRecordSendMasterHandshake in libIOTCAPIs.so.
pub const PUB_RSA_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn8roKGV4ukAPhiOD+Asz\neCXWjBIycEIJplBpiDcNRzfoJLXwLXCYSYsH812HaD5NnzpH7jPh/FAORNXoBkGJ\ndnje299ddL7CXU1bCasSAes6FXI1XlLsBOzEW2IdM9DCyhWBx9EUOCgYHA6A+KmG\nmsfVOXF5eNbT6Nk7fSjGrpRGj6wDuyyhrAPuLw+yMCsyoOVMlNpziBQJqcRO5xrP\n3/xHsT9f5ww/udb4+fAIlrGwv4zAkg+D2mm353G9MFoQhvd+odoa8CVrGvsetXul\npfbMkBfvgKTj7UJRb78PJQJj9WmixJc7KDKgqJNGZ1tkMwWdFfYcZH3I3kmlu6mt\nhwIDAQAB\n-----END PUBLIC KEY-----";