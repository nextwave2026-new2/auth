package com.nextwave.auth.exception;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import com.nextwave.auth.dto.response.ApiResponse;

import lombok.extern.slf4j.Slf4j;

/**
 * Auth Exception Handler
 * 
 * Handles all exceptions thrown by the auth service and returns
 * appropriate HTTP responses with error messages.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Slf4j
@RestControllerAdvice(basePackages = "com.nextwave.auth")
public class AuthExceptionHandler {
    
    /**
     * Handle validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationExceptions(
            MethodArgumentNotValidException ex
    ) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        
        log.error("Validation error: {}", errors);
        
        ApiResponse<Map<String, String>> response = ApiResponse.error("Validation failed", errors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
    
    /**
     * Handle resource not found
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceNotFoundException(
            ResourceNotFoundException ex,
            WebRequest request
    ) {
        log.error("Resource not found: {}", ex.getMessage());
        
        ApiResponse<Void> response = ApiResponse.error(ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }
    
    /**
     * Handle resource already exists
     */
    @ExceptionHandler(ResourceAlreadyExistsException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceAlreadyExistsException(
            ResourceAlreadyExistsException ex,
            WebRequest request
    ) {
        log.error("Resource already exists: {}", ex.getMessage());
        
        ApiResponse<Void> response = ApiResponse.error(ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }
    
    /**
     * Handle bad request
     */
    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadRequestException(
            BadRequestException ex,
            WebRequest request
    ) {
        log.error("Bad request: {}", ex.getMessage());
        
        ApiResponse<Void> response = ApiResponse.error(ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
    
    /**
     * Handle bad credentials
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadCredentialsException(
            BadCredentialsException ex,
            WebRequest request
    ) {
        log.error("Bad credentials: {}", ex.getMessage());
        
        ApiResponse<Void> response = ApiResponse.error("Invalid username/email or password");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }
    
    /**
     * Handle account locked
     */
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ApiResponse<Void>> handleLockedException(
            LockedException ex,
            WebRequest request
    ) {
        log.error("Account locked: {}", ex.getMessage());
        
        ApiResponse<Void> response = ApiResponse.error(ex.getMessage());
        return ResponseEntity.status(HttpStatus.LOCKED).body(response);
    }
    
    /**
     * Handle all other exceptions
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGlobalException(
            Exception ex,
            WebRequest request
    ) {
        log.error("Unexpected error: ", ex);
        
        // In development, return the actual error message for debugging
        String message = "An unexpected error occurred: " + ex.getMessage();
        ApiResponse<Void> response = ApiResponse.error(message);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
