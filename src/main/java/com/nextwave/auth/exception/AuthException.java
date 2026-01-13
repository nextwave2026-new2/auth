package com.nextwave.auth.exception;

/**
 * Base exception for the authentication service
 * 
 * @author NextWave Team
 * @version 1.0
 */
public class AuthException extends RuntimeException {
    
    public AuthException(String message) {
        super(message);
    }
    
    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
