package com.nextwave.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Authentication Response DTO
 * 
 * Returned after successful login or token refresh.
 * Contains access token, refresh token, and user information.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthResponse {
    
    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
    private Long expiresIn; // in seconds
    private UserInfo user;
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class UserInfo {
        private Long id;
        private String username;
        private String email;
        private String firstName;
        private String lastName;
        private String phoneNumber;
        private Boolean emailVerified;
        private Set<String> roles;
        private Set<String> permissions;
        private LocalDateTime lastLogin;
    }
}
