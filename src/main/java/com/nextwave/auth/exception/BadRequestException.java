package com.nextwave.auth.exception;

/**
 * Exception thrown for bad requests
 * 
 * @author NextWave Team
 * @version 1.0
 */
public class BadRequestException extends AuthException {
    
    public BadRequestException(String message) {
        super(message);
    }
    
    public BadRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
