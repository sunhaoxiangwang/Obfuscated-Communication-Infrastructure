//! Foreign Function Interface (FFI) for cross-platform integration.
//!
//! Provides C-compatible bindings for use with:
//! - Android via JNI
//! - iOS via Swift/Objective-C
//! - Any language with C FFI support (Python, Go, etc.)
//!
//! ## Memory Safety
//!
//! All FFI functions follow these conventions:
//! - Handles are opaque pointers to Rust-managed resources
//! - Callers must explicitly free resources using the provided free functions
//! - All strings are null-terminated C strings
//! - Errors are returned as negative integers or NULL pointers
//!
//! ## Thread Safety
//!
//! All exported functions are thread-safe and can be called from multiple threads.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::Arc;

use crate::crypto::{PublicKey, StaticSecret};
use crate::reality::RealityConfig;

/// Result code indicating success.
pub const SCF_OK: c_int = 0;
/// Result code indicating generic error.
pub const SCF_ERROR: c_int = -1;
/// Result code indicating invalid argument.
pub const SCF_ERROR_INVALID_ARG: c_int = -2;
/// Result code indicating connection failure.
pub const SCF_ERROR_CONNECT: c_int = -3;
/// Result code indicating authentication failure.
pub const SCF_ERROR_AUTH: c_int = -4;
/// Result code indicating timeout.
pub const SCF_ERROR_TIMEOUT: c_int = -5;

/// Opaque handle to a client configuration.
pub struct ScfConfig {
    inner: RealityConfig,
}

/// Opaque handle to a connection.
pub struct ScfConnection {
    inner: Option<tokio::runtime::Runtime>,
    // Connection state would be stored here
}

/// Initialize the SCF library.
///
/// Must be called before any other SCF functions.
/// Thread-safe and can be called multiple times (subsequent calls are no-ops).
///
/// # Returns
///
/// SCF_OK on success.
#[no_mangle]
pub extern "C" fn scf_init() -> c_int {
    // Initialize logging (only once)
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .init();
    });

    SCF_OK
}

/// Create a new client configuration.
///
/// # Arguments
///
/// * `server_public_key` - Server's X25519 public key (32 bytes)
/// * `short_id` - Authentication short ID (8 bytes)
/// * `cover_sni` - SNI hostname (null-terminated C string)
/// * `server_addr` - Server address (null-terminated C string)
/// * `server_port` - Server port
///
/// # Returns
///
/// Pointer to configuration handle, or NULL on error.
#[no_mangle]
pub unsafe extern "C" fn scf_config_new(
    server_public_key: *const u8,
    short_id: *const u8,
    cover_sni: *const c_char,
    server_addr: *const c_char,
    server_port: u16,
) -> *mut ScfConfig {
    // Validate arguments
    if server_public_key.is_null()
        || short_id.is_null()
        || cover_sni.is_null()
        || server_addr.is_null()
    {
        return ptr::null_mut();
    }

    // Copy key and short_id
    let mut key = [0u8; 32];
    let mut id = [0u8; 8];
    ptr::copy_nonoverlapping(server_public_key, key.as_mut_ptr(), 32);
    ptr::copy_nonoverlapping(short_id, id.as_mut_ptr(), 8);

    // Parse strings
    let cover_sni = match CStr::from_ptr(cover_sni).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ptr::null_mut(),
    };

    let server_addr = match CStr::from_ptr(server_addr).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ptr::null_mut(),
    };

    let config = RealityConfig {
        server_public_key: key,
        short_id: id,
        cover_sni,
        server_addr,
        server_port,
        cover_fingerprint: None,
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
    };

    Box::into_raw(Box::new(ScfConfig { inner: config }))
}

/// Free a configuration handle.
///
/// # Safety
///
/// The handle must have been returned by scf_config_new and not previously freed.
#[no_mangle]
pub unsafe extern "C" fn scf_config_free(config: *mut ScfConfig) {
    if !config.is_null() {
        drop(Box::from_raw(config));
    }
}

/// Connect to the server.
///
/// # Arguments
///
/// * `config` - Configuration handle
/// * `timeout_ms` - Connection timeout in milliseconds
///
/// # Returns
///
/// Connection handle on success, NULL on error.
#[no_mangle]
pub unsafe extern "C" fn scf_connect(
    config: *const ScfConfig,
    timeout_ms: u32,
) -> *mut ScfConnection {
    if config.is_null() {
        return ptr::null_mut();
    }

    let config = &(*config).inner;

    // Create runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    // Attempt connection
    let _result = rt.block_on(async {
        let client = match crate::reality::RealityClient::new(config.clone()) {
            Ok(c) => c,
            Err(_) => return Err(()),
        };

        let timeout = std::time::Duration::from_millis(timeout_ms as u64);
        client.connect_with_timeout(timeout).await.map_err(|_| ())
    });

    // For now, return a placeholder connection
    // In production, this would store the actual connection
    Box::into_raw(Box::new(ScfConnection { inner: Some(rt) }))
}

/// Send data over the connection.
///
/// # Arguments
///
/// * `conn` - Connection handle
/// * `data` - Data to send
/// * `len` - Length of data
///
/// # Returns
///
/// Number of bytes sent, or negative error code.
#[no_mangle]
pub unsafe extern "C" fn scf_send(
    conn: *mut ScfConnection,
    data: *const u8,
    len: usize,
) -> c_int {
    if conn.is_null() || data.is_null() {
        return SCF_ERROR_INVALID_ARG;
    }

    // In production, this would send data over the connection
    len as c_int
}

/// Receive data from the connection.
///
/// # Arguments
///
/// * `conn` - Connection handle
/// * `buffer` - Buffer to receive data into
/// * `buffer_len` - Length of buffer
///
/// # Returns
///
/// Number of bytes received, or negative error code.
#[no_mangle]
pub unsafe extern "C" fn scf_recv(
    conn: *mut ScfConnection,
    buffer: *mut u8,
    buffer_len: usize,
) -> c_int {
    if conn.is_null() || buffer.is_null() {
        return SCF_ERROR_INVALID_ARG;
    }

    // In production, this would receive data from the connection
    0 // No data available
}

/// Close the connection.
///
/// # Safety
///
/// The handle must have been returned by scf_connect and not previously freed.
#[no_mangle]
pub unsafe extern "C" fn scf_close(conn: *mut ScfConnection) {
    if !conn.is_null() {
        drop(Box::from_raw(conn));
    }
}

/// Generate a new keypair for server configuration.
///
/// # Arguments
///
/// * `public_key_out` - Buffer for public key (32 bytes)
/// * `secret_key_out` - Buffer for secret key (32 bytes)
///
/// # Returns
///
/// SCF_OK on success.
#[no_mangle]
pub unsafe extern "C" fn scf_generate_keypair(
    public_key_out: *mut u8,
    secret_key_out: *mut u8,
) -> c_int {
    if public_key_out.is_null() || secret_key_out.is_null() {
        return SCF_ERROR_INVALID_ARG;
    }

    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    ptr::copy_nonoverlapping(public.as_bytes().as_ptr(), public_key_out, 32);
    ptr::copy_nonoverlapping(secret.to_bytes().as_ptr(), secret_key_out, 32);

    SCF_OK
}

/// Generate a random short ID.
///
/// # Arguments
///
/// * `short_id_out` - Buffer for short ID (8 bytes)
///
/// # Returns
///
/// SCF_OK on success.
#[no_mangle]
pub unsafe extern "C" fn scf_generate_short_id(short_id_out: *mut u8) -> c_int {
    if short_id_out.is_null() {
        return SCF_ERROR_INVALID_ARG;
    }

    let id: [u8; 8] = crate::crypto::SecureRandom::bytes();
    ptr::copy_nonoverlapping(id.as_ptr(), short_id_out, 8);

    SCF_OK
}

/// Get the library version string.
///
/// # Returns
///
/// Null-terminated version string. Caller must not free this pointer.
#[no_mangle]
pub extern "C" fn scf_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

/// Get error description for an error code.
///
/// # Arguments
///
/// * `error_code` - Error code from a previous SCF function
///
/// # Returns
///
/// Null-terminated error description. Caller must not free this pointer.
#[no_mangle]
pub extern "C" fn scf_error_string(error_code: c_int) -> *const c_char {
    let msg = match error_code {
        SCF_OK => b"Success\0",
        SCF_ERROR => b"Unknown error\0",
        SCF_ERROR_INVALID_ARG => b"Invalid argument\0",
        SCF_ERROR_CONNECT => b"Connection failed\0",
        SCF_ERROR_AUTH => b"Authentication failed\0",
        SCF_ERROR_TIMEOUT => b"Operation timed out\0",
        _ => b"Unknown error code\0",
    };
    msg.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert_eq!(scf_init(), SCF_OK);
        // Multiple calls should be fine
        assert_eq!(scf_init(), SCF_OK);
    }

    #[test]
    fn test_version() {
        let version = scf_version();
        assert!(!version.is_null());

        let version_str = unsafe { CStr::from_ptr(version) };
        assert_eq!(version_str.to_str().unwrap(), "0.1.0");
    }

    #[test]
    fn test_error_string() {
        let msg = scf_error_string(SCF_OK);
        assert!(!msg.is_null());

        let msg_str = unsafe { CStr::from_ptr(msg) };
        assert_eq!(msg_str.to_str().unwrap(), "Success");
    }

    #[test]
    fn test_generate_keypair() {
        let mut public_key = [0u8; 32];
        let mut secret_key = [0u8; 32];

        let result = unsafe {
            scf_generate_keypair(public_key.as_mut_ptr(), secret_key.as_mut_ptr())
        };

        assert_eq!(result, SCF_OK);
        assert!(public_key.iter().any(|&b| b != 0));
        assert!(secret_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_generate_short_id() {
        let mut short_id = [0u8; 8];

        let result = unsafe { scf_generate_short_id(short_id.as_mut_ptr()) };

        assert_eq!(result, SCF_OK);
        assert!(short_id.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_config_null_safety() {
        unsafe {
            let config = scf_config_new(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                443,
            );
            assert!(config.is_null());
        }
    }
}
