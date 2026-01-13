package com.nextwave.auth.service;

import com.nextwave.auth.dto.request.*;
import com.nextwave.auth.dto.response.AuthResponse;
import com.nextwave.common.entity.*;
import com.nextwave.auth.exception.*;
import com.nextwave.auth.repository.*;
import com.nextwave.auth.security.JwtTokenProvider;
import com.nextwave.auth.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Authentication Service
 * 
 * Handles all authentication-related business logic:
 * - User registration
 * - Login/Logout
 * - Password reset
 * - Email verification
 * - Token management
 * 
 * Design Patterns:
 * - Service Layer Pattern
 * - Transaction Management
 * - Exception Handling
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    
    private final EmailService emailService;
    
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final String DEFAULT_ROLE = "ROLE_USER";
    
    /**
     * Register a new user
     * 
     * Steps:
     * 1. Validate registration data
     * 2. Check if email/username already exists
     * 3. Create user entity with encoded password
     * 4. Assign default role
     * 5. Generate email verification token
     * 6. Send verification email
     * 
     * @param request Registration request data
     * @return Success message
     * @throws ResourceAlreadyExistsException if email/username exists
     * @throws BadRequestException if passwords don't match
     */
    @Transactional
    public String register(RegisterRequest request) {
        log.info("Processing registration for email: {}", request.getEmail());
        
        // Validate password match
        if (!request.isPasswordMatching()) {
            throw new BadRequestException("Passwords do not match");
        }
        
        // Check if email already exists
        if (userRepository.existsByEmailIgnoreCase(request.getEmail())) {
            throw new ResourceAlreadyExistsException("Email is already registered");
        }
        
        // Check if username already exists
        if (userRepository.existsByUsernameIgnoreCase(request.getUsername())) {
            throw new ResourceAlreadyExistsException("Username is already taken");
        }
        
        // Create user entity
        User user = User.builder()
                .email(request.getEmail().toLowerCase())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .emailVerified(false)
                .accountEnabled(true)
                .accountLocked(false)
                .failedLoginAttempts(0)
                .deleted(false)
                .build();
        
        // Assign default role
        Role userRole = roleRepository.findByName(DEFAULT_ROLE)
                .orElseGet(() -> createDefaultRole());
        user.addRole(userRole);
        
        // Save user
        user = userRepository.save(user);
        log.info("User registered successfully: {}", user.getEmail());
        
        // Generate and send email verification token
        try {
            String verificationToken = generateEmailVerificationToken(user);
            emailService.sendVerificationEmail(user.getEmail(), verificationToken);
            log.info("Verification email sent to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}. Error: {}", user.getEmail(), e.getMessage());
            // Continue registration even if email fails
        }
        
        return "Registration successful. Please check your email to verify your account.";
    }
    
    /**
     * Login user
     * 
     * Steps:
     * 1. Authenticate credentials
     * 2. Check account status (locked, disabled, deleted)
     * 3. Reset failed login attempts
     * 4. Update last login time
     * 5. Generate access and refresh tokens
     * 6. Save refresh token
     * 
     * @param request Login credentials
     * @return Authentication response with tokens and user info
     * @throws BadCredentialsException if credentials are invalid
     * @throws LockedException if account is locked
     * @throws ResourceNotFoundException if user not found
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        log.info("Processing login for: {}", request.getEmailOrUsername());
        
        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmailOrUsername(),
                            request.getPassword()
                    )
            );
            
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            
            // Load full user entity
            User user = userRepository.findById(userPrincipal.getId())
                    .orElseThrow(() -> new ResourceNotFoundException("User not found"));
            
            // Check if account is locked
            if (user.getAccountLocked()) {
                throw new LockedException("Account is locked due to multiple failed login attempts. " +
                        "Please contact support or reset your password.");
            }
            
            // Check if account is enabled
            if (!user.getAccountEnabled()) {
                throw new BadRequestException("Account is disabled. Please contact support.");
            }
            
            // Reset failed login attempts
            user.resetFailedLoginAttempts();
            
            // Update last login
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
            
            // Generate tokens
            String accessToken = jwtTokenProvider.generateAccessToken(userPrincipal);
            String refreshToken = jwtTokenProvider.generateRefreshToken(userPrincipal);
            
            // Save refresh token
            saveRefreshToken(user, refreshToken);
            
            log.info("User logged in successfully: {}", user.getEmail());
            
            // Build response
            return buildAuthResponse(user, accessToken, refreshToken);
            
        } catch (AuthenticationException ex) {
            handleFailedLogin(request.getEmailOrUsername());
            throw new BadCredentialsException("Invalid username/email or password");
        }
    }
    
    /**
     * Refresh access token
     * 
     * Steps:
     * 1. Validate refresh token
     * 2. Check if token exists and is valid
     * 3. Generate new access token
     * 4. Optionally generate new refresh token
     * 
     * @param request Refresh token request
     * @return New authentication response
     * @throws BadRequestException if token is invalid
     */
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        log.info("Processing token refresh");
        
        String refreshTokenStr = request.getRefreshToken();
        
        // Validate refresh token format
        if (!jwtTokenProvider.validateToken(refreshTokenStr)) {
            throw new BadRequestException("Invalid refresh token");
        }
        
        // Find refresh token in database
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr)
                .orElseThrow(() -> new BadRequestException("Refresh token not found"));
        
        // Validate token
        if (!refreshToken.isValid()) {
            throw new BadRequestException("Refresh token is expired or revoked");
        }
        
        User user = refreshToken.getUser();
        UserPrincipal userPrincipal = UserPrincipal.create(user);
        
        // Generate new access token
        String newAccessToken = jwtTokenProvider.generateAccessToken(userPrincipal);
        
        // Generate new refresh token (optional - token rotation)
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(userPrincipal);
        
        // Revoke old refresh token
        refreshToken.revoke();
        refreshTokenRepository.save(refreshToken);
        
        // Save new refresh token
        saveRefreshToken(user, newRefreshToken);
        
        log.info("Token refreshed successfully for user: {}", user.getEmail());
        
        return buildAuthResponse(user, newAccessToken, newRefreshToken);
    }
    
    /**
     * Forgot password - send reset email
     * 
     * Steps:
     * 1. Find user by email
     * 2. Generate password reset token
     * 3. Send reset email
     * 
     * @param request Forgot password request
     * @return Success message
     */
    @Transactional
    public String forgotPassword(ForgotPasswordRequest request) {
        log.info("Processing forgot password request for email: {}", request.getEmail());
        
        User user = userRepository.findByEmailIgnoreCase(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("No account found with this email"));
        
        // Check if account is deleted
        if (user.getDeleted()) {
            throw new BadRequestException("Account has been deleted");
        }
        
        // Invalidate old password reset tokens
        passwordResetTokenRepository.consumeAllUserTokens(user, LocalDateTime.now());
        
        // Generate new token
        String resetToken = generatePasswordResetToken(user);
        
        // Send email
        emailService.sendPasswordResetEmail(user.getEmail(), resetToken);
        
        log.info("Password reset email sent to: {}", user.getEmail());
        
        return "Password reset instructions have been sent to your email";
    }
    
    /**
     * Reset password with token
     * 
     * Steps:
     * 1. Validate token
     * 2. Validate passwords match
     * 3. Update password
     * 4. Consume token
     * 5. Revoke all refresh tokens
     * 6. Unlock account if locked
     * 
     * @param request Reset password request
     * @return Success message
     * @throws BadRequestException if token is invalid or passwords don't match
     */
    @Transactional
    public String resetPassword(ResetPasswordRequest request) {
        log.info("Processing password reset");
        
        // Validate passwords match
        if (!request.isPasswordMatching()) {
            throw new BadRequestException("Passwords do not match");
        }
        
        // Find and validate token
        PasswordResetToken resetToken = passwordResetTokenRepository
                .findValidToken(request.getToken(), LocalDateTime.now())
                .orElseThrow(() -> new BadRequestException("Invalid or expired reset token"));
        
        User user = resetToken.getUser();
        
        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        
        // Unlock account if locked
        if (user.getAccountLocked()) {
            user.unlockAccount();
        }
        
        // Consume token
        resetToken.consume();
        passwordResetTokenRepository.save(resetToken);
        
        // Revoke all refresh tokens
        refreshTokenRepository.revokeAllUserTokens(user);
        
        userRepository.save(user);
        
        log.info("Password reset successfully for user: {}", user.getEmail());
        
        return "Password has been reset successfully. Please login with your new password.";
    }
    
    /**
     * Change password for authenticated user
     * 
     * @param userId User ID
     * @param request Change password request
     * @return Success message
     */
    @Transactional
    public String changePassword(Long userId, ChangePasswordRequest request) {
        log.info("Processing password change for user ID: {}", userId);
        
        // Validate passwords match
        if (!request.isPasswordMatching()) {
            throw new BadRequestException("New passwords do not match");
        }
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadCredentialsException("Current password is incorrect");
        }
        
        // Check if new password is same as current
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new BadRequestException("New password must be different from current password");
        }
        
        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        
        // Revoke all refresh tokens
        refreshTokenRepository.revokeAllUserTokens(user);
        
        log.info("Password changed successfully for user: {}", user.getEmail());
        
        return "Password changed successfully. Please login again.";
    }
    
    /**
     * Verify email with token
     * 
     * @param token Verification token
     * @return Success message
     */
    @Transactional
    public String verifyEmail(String token) {
        log.info("Processing email verification");
        
        EmailVerificationToken verificationToken = emailVerificationTokenRepository
                .findValidToken(token, LocalDateTime.now())
                .orElseThrow(() -> new BadRequestException("Invalid or expired verification token"));
        
        User user = verificationToken.getUser();
        
        if (user.getEmailVerified()) {
            throw new BadRequestException("Email is already verified");
        }
        
        // Mark email as verified
        user.setEmailVerified(true);
        userRepository.save(user);
        
        // Consume token
        verificationToken.consume();
        emailVerificationTokenRepository.save(verificationToken);
        
        log.info("Email verified successfully for user: {}", user.getEmail());
        
        return "Email verified successfully";
    }
    
    /**
     * Resend verification email
     * 
     * @param email User email
     * @return Success message
     */
    @Transactional
    public String resendVerificationEmail(String email) {
        log.info("Resending verification email to: {}", email);
        
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        if (user.getEmailVerified()) {
            throw new BadRequestException("Email is already verified");
        }
        
        // Delete old verification tokens
        emailVerificationTokenRepository.deleteByUser(user);
        
        // Generate new token
        String verificationToken = generateEmailVerificationToken(user);
        
        // Send email
        emailService.sendVerificationEmail(user.getEmail(), verificationToken);
        
        return "Verification email has been resent";
    }
    
    /**
     * Logout user - revoke refresh token
     * 
     * @param refreshToken Refresh token to revoke
     * @return Success message
     */
    @Transactional
    public String logout(String refreshToken) {
        log.info("Processing logout");
        
        refreshTokenRepository.findByToken(refreshToken)
                .ifPresent(token -> {
                    token.revoke();
                    refreshTokenRepository.save(token);
                });
        
        return "Logged out successfully";
    }
    
    // ========== Helper Methods ==========
    
    /**
     * Handle failed login attempt
     */
    private void handleFailedLogin(String usernameOrEmail) {
        userRepository.findByUsernameIgnoreCase(usernameOrEmail)
                .or(() -> userRepository.findByEmailIgnoreCase(usernameOrEmail))
                .ifPresent(user -> {
                    user.incrementFailedLoginAttempts();
                    
                    if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                        user.lockAccount();
                        log.warn("Account locked due to failed login attempts: {}", user.getEmail());
                    }
                    
                    userRepository.save(user);
                });
    }
    
    /**
     * Save refresh token to database
     */
    private void saveRefreshToken(User user, String token) {
        LocalDateTime expiresAt = LocalDateTime.now()
                .plusSeconds(jwtTokenProvider.getRefreshExpirationInMs() / 1000);
        
        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .expiresAt(expiresAt)
                .revoked(false)
                .build();
        
        refreshTokenRepository.save(refreshToken);
    }
    
    /**
     * Generate email verification token
     */
    private String generateEmailVerificationToken(User user) {
        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(24);
        
        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .token(token)
                .user(user)
                .expiresAt(expiresAt)
                .consumed(false)
                .build();
        
        emailVerificationTokenRepository.save(verificationToken);
        
        return token;
    }
    
    /**
     * Generate password reset token
     */
    private String generatePasswordResetToken(User user) {
        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(1);
        
        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .user(user)
                .expiresAt(expiresAt)
                .consumed(false)
                .build();
        
        passwordResetTokenRepository.save(resetToken);
        
        return token;
    }
    
    /**
     * Create default user role if not exists
     */
    private Role createDefaultRole() {
        Role role = Role.builder()
                .name(DEFAULT_ROLE)
                .description("Default user role")
                .build();
        
        return roleRepository.save(role);
    }
    
    /**
     * Build authentication response
     */
    private AuthResponse buildAuthResponse(User user, String accessToken, String refreshToken) {
        Set<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
        
        Set<String> permissions = user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::getName)
                .collect(Collectors.toSet());
        
        AuthResponse.UserInfo userInfo = AuthResponse.UserInfo.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .emailVerified(user.getEmailVerified())
                .roles(roles)
                .permissions(permissions)
                .lastLogin(user.getLastLogin())
                .build();
        
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getJwtExpirationInSeconds())
                .user(userInfo)
                .build();
    }
}
