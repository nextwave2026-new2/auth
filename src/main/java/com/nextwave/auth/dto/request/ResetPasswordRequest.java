package com.nextwave.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Reset Password Request DTO
 * 
 * Used to reset password with a valid token.
 * Token is sent via email after forgot password request.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResetPasswordRequest {
    
    @NotBlank(message = "Token is required")
    private String token;
    
    @NotBlank(message = "New password is required")
    @Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
    private String newPassword;
    
    @NotBlank(message = "Password confirmation is required")
    private String confirmPassword;
    
    /**
     * Check if passwords match
     */
    public boolean isPasswordMatching() {
        return newPassword != null && newPassword.equals(confirmPassword);
    }
}
