package com.nextwave.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nextwave.auth.dto.request.ChangePasswordRequest;
import com.nextwave.auth.dto.request.ForgotPasswordRequest;
import com.nextwave.auth.dto.request.LoginRequest;
import com.nextwave.auth.dto.request.RefreshTokenRequest;
import com.nextwave.auth.dto.request.RegisterRequest;
import com.nextwave.auth.dto.request.ResetPasswordRequest;
import com.nextwave.auth.dto.response.ApiResponse;
import com.nextwave.auth.dto.response.AuthResponse;
import com.nextwave.auth.security.UserPrincipal;
import com.nextwave.auth.service.AuthService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Authentication Controller
 * REST API endpoints for authentication operations
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration request received for email: {}", request.getEmail());
        String message = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(message));
    }
    
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login request received for: {}", request.getEmailOrUsername());
        AuthResponse authResponse = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success(authResponse, "Login successful"));
    }
    
    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Token refresh request received");
        AuthResponse authResponse = authService.refreshToken(request);
        return ResponseEntity.ok(ApiResponse.success(authResponse, "Token refreshed successfully"));
    }
    
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout request received");
        String message = authService.logout(request.getRefreshToken());
        return ResponseEntity.ok(ApiResponse.success(message));
    }
    
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        log.info("Forgot password request received for email: {}", request.getEmail());
        String message = authService.forgotPassword(request);
        return ResponseEntity.ok(ApiResponse.success(message));
    }
    
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        log.info("Reset password request received");
        String message = authService.resetPassword(request);
        return ResponseEntity.ok(ApiResponse.success(message));
    }
    
    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @AuthenticationPrincipal UserPrincipal userPrincipal,
            @Valid @RequestBody ChangePasswordRequest request
    ) {
        log.info("Change password request received for user ID: {}", userPrincipal.getId());
        String message = authService.changePassword(userPrincipal.getId(), request);
        return ResponseEntity.ok(ApiResponse.success(message));
    }
    
    @GetMapping("/verify-email")
    public ResponseEntity<ApiResponse<Void>> verifyEmail(@RequestParam String token) {
        log.info("Email verification request received");
        String message = authService.verifyEmail(token);
        return ResponseEntity.ok(ApiResponse.success(message));
    }
    
    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<Void>> resendVerificationEmail(@RequestParam String email) {
        log.info("Resend verification request received for email: {}", email);
        String message = authService.resendVerificationEmail(email);
        return ResponseEntity.ok(ApiResponse.success(message));
    }
    
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserInfo>> getCurrentUser(@AuthenticationPrincipal UserPrincipal userPrincipal) {
        log.info("Get current user request received for user ID: {}", userPrincipal.getId());
        UserInfo userInfo = UserInfo.builder()
                .id(userPrincipal.getId())
                .username(userPrincipal.getUsername())
                .email(userPrincipal.getEmail())
                .build();
        return ResponseEntity.ok(ApiResponse.success(userInfo, "User info retrieved successfully"));
    }
    
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> health() {
        return ResponseEntity.ok(ApiResponse.success("Auth service is running", "healthy"));
    }
    
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class UserInfo {
        private Long id;
        private String username;
        private String email;
    }
}
