package com.nextwave.auth.config;

import java.time.LocalDateTime;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

import com.nextwave.auth.repository.EmailVerificationTokenRepository;
import com.nextwave.auth.repository.PasswordResetTokenRepository;
import com.nextwave.auth.repository.RefreshTokenRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Application Configuration
 * 
 * Contains initialization logic and scheduled tasks.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Slf4j
@Configuration
@EnableScheduling
@RequiredArgsConstructor
public class AppConfig {
    
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    
    /**
     * Scheduled cleanup of expired tokens
     */
    @Scheduled(cron = "0 0 2 * * *")
    public void scheduledCleanupExpiredTokens() {
        try {
            cleanupExpiredTokens();
        } catch (Exception e) {
            log.error("Could not cleanup expired tokens in scheduled task", e);
        }
    }
    
    /**
     * Cleanup expired tokens
     */
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        
        refreshTokenRepository.deleteExpiredTokens(now);
        passwordResetTokenRepository.deleteExpiredTokens(now);
        emailVerificationTokenRepository.deleteExpiredTokens(now);
        
        log.info("Expired tokens cleaned up successfully");
    }
}
