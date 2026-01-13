package com.nextwave.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Email Service
 * 
 * Handles sending emails for:
 * - Email verification
 * - Password reset
 * - Welcome messages
 * - Account notifications
 * 
 * Uses Spring Mail with async processing.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {
    
    private final JavaMailSender mailSender;
    
    @Value("${password-reset.email-from}")
    private String fromEmail;
    
    @Value("${password-reset.reset-url}")
    private String resetPasswordUrl;
    
    @Value("${spring.application.name}")
    private String appName;
    
    /**
     * Send email verification email
     */
    @Async
    public void sendVerificationEmail(String toEmail, String token) {
        try {
            String subject = "Verify Your Email - " + appName;
            String verificationUrl = resetPasswordUrl.replace("/reset-password", "/verify-email") + "?token=" + token;
            
            String body = String.format("""
                    Hello,
                    
                    Thank you for registering with %s!
                    
                    Please click the link below to verify your email address:
                    %s
                    
                    This link will expire in 24 hours.
                    
                    If you didn't create an account, please ignore this email.
                    
                    Best regards,
                    %s Team
                    """, appName, verificationUrl, appName);
            
            sendEmail(toEmail, subject, body);
            log.info("Verification email sent to: {}", toEmail);
            
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}", toEmail, e);
        }
    }
    
    /**
     * Send password reset email
     */
    @Async
    public void sendPasswordResetEmail(String toEmail, String token) {
        try {
            String subject = "Password Reset Request - " + appName;
            String resetUrl = resetPasswordUrl + "?token=" + token;
            
            String body = String.format("""
                    Hello,
                    
                    We received a request to reset your password for your %s account.
                    
                    Please click the link below to reset your password:
                    %s
                    
                    This link will expire in 1 hour.
                    
                    If you didn't request a password reset, please ignore this email or contact support if you have concerns.
                    
                    Best regards,
                    %s Team
                    """, appName, resetUrl, appName);
            
            sendEmail(toEmail, subject, body);
            log.info("Password reset email sent to: {}", toEmail);
            
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", toEmail, e);
        }
    }
    
    /**
     * Send welcome email after successful registration
     */
    @Async
    public void sendWelcomeEmail(String toEmail, String userName) {
        try {
            String subject = "Welcome to " + appName + "!";
            
            String body = String.format("""
                    Hello %s,
                    
                    Welcome to %s!
                    
                    Your account has been successfully created and verified.
                    
                    You can now enjoy all the features of our platform.
                    
                    If you have any questions or need assistance, please don't hesitate to contact our support team.
                    
                    Best regards,
                    %s Team
                    """, userName, appName, appName);
            
            sendEmail(toEmail, subject, body);
            log.info("Welcome email sent to: {}", toEmail);
            
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", toEmail, e);
        }
    }
    
    /**
     * Send account locked notification
     */
    @Async
    public void sendAccountLockedEmail(String toEmail) {
        try {
            String subject = "Account Security Alert - " + appName;
            
            String body = String.format("""
                    Hello,
                    
                    Your %s account has been locked due to multiple failed login attempts.
                    
                    For security reasons, we've temporarily locked your account.
                    
                    To unlock your account:
                    1. Reset your password using the "Forgot Password" link
                    2. Or contact our support team
                    
                    If you didn't attempt to login, please reset your password immediately as someone may be trying to access your account.
                    
                    Best regards,
                    %s Team
                    """, appName, appName);
            
            sendEmail(toEmail, subject, body);
            log.info("Account locked email sent to: {}", toEmail);
            
        } catch (Exception e) {
            log.error("Failed to send account locked email to: {}", toEmail, e);
        }
    }
    
    /**
     * Generic send email method
     */
    private void sendEmail(String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        
        mailSender.send(message);
    }
}
