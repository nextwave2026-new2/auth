package com.nextwave.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login Request DTO
 * 
 * Used for user authentication.
 * Supports login with email or username.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginRequest {
    
    @NotBlank(message = "Email or username is required")
    private String emailOrUsername;
    
    @NotBlank(message = "Password is required")
    private String password;
    
    /**
     * Remember me option for extended session
     */
    @Builder.Default
    private Boolean rememberMe = false;
}
