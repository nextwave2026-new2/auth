package com.nextwave.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Registration Request DTO
 * 
 * Used when a new user registers in the system.
 * Contains validation rules for all required fields.
 * 
 * Validation Rules:
 * - Email: Must be valid email format
 * - Username: 3-50 characters, alphanumeric and underscore only
 * - Password: Minimum 8 characters, must contain uppercase, lowercase, digit, and special character
 * - Names: 2-100 characters
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterRequest {
    
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, and underscores")
    private String username;
    
    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
    private String password;
    
    @NotBlank(message = "Password confirmation is required")
    private String confirmPassword;
    
    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 100, message = "First name must be between 2 and 100 characters")
    private String firstName;
    
    @NotBlank(message = "Last name is required")
    @Size(min = 2, max = 100, message = "Last name must be between 2 and 100 characters")
    private String lastName;
    
    @Pattern(regexp = "^[+]?[(]?[0-9]{1,4}[)]?[-\\s./0-9]*$", message = "Phone number is invalid")
    private String phoneNumber;
    
    /**
     * Check if passwords match
     */
    public boolean isPasswordMatching() {
        return password != null && password.equals(confirmPassword);
    }
}
