package com.nextwave.auth.exception;

/**
 * Exception thrown when requested resource is not found
 * 
 * @author NextWave Team
 * @version 1.0
 */
public class ResourceNotFoundException extends AuthException {
    
    public ResourceNotFoundException(String message) {
        super(message);
    }
    
    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
