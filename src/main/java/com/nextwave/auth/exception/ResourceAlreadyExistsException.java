package com.nextwave.auth.exception;

/**
 * Exception thrown when a resource already exists
 * 
 * @author NextWave Team
 * @version 1.0
 */
public class ResourceAlreadyExistsException extends AuthException {
    
    public ResourceAlreadyExistsException(String message) {
        super(message);
    }
    
    public ResourceAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}
