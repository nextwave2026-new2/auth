package com.nextwave.auth.repository;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.nextwave.common.entity.EmailVerificationToken;
import com.nextwave.common.entity.User;

/**
 * EmailVerificationToken Repository - Data access layer for EmailVerificationToken entity
 * 
 * Manages email verification tokens.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {
    
    /**
     * Find email verification token by token string
     */
    Optional<EmailVerificationToken> findByToken(String token);
    
    /**
     * Find valid token by token string
     */
    @Query("SELECT evt FROM EmailVerificationToken evt WHERE evt.token = :token " +
           "AND evt.consumed = false AND evt.expiresAt > :now")
    Optional<EmailVerificationToken> findValidToken(@Param("token") String token, @Param("now") LocalDateTime now);
    
    /**
     * Find token by user
     */
    Optional<EmailVerificationToken> findByUser(User user);
    
    /**
     * Delete expired tokens
     */
    @Modifying
    @Query("DELETE FROM EmailVerificationToken evt WHERE evt.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
    
    /**
     * Delete all tokens for a user
     */
    @Modifying
    @Query("DELETE FROM EmailVerificationToken evt WHERE evt.user = :user")
    void deleteByUser(@Param("user") User user);
}
