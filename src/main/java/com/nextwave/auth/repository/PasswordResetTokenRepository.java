package com.nextwave.auth.repository;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.nextwave.common.entity.PasswordResetToken;
import com.nextwave.common.entity.User;

/**
 * PasswordResetToken Repository - Data access layer for PasswordResetToken entity
 * 
 * Manages password reset tokens.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    
    /**
     * Find password reset token by token string
     */
    Optional<PasswordResetToken> findByToken(String token);
    
    /**
     * Find valid token by token string
     */
    @Query("SELECT prt FROM PasswordResetToken prt WHERE prt.token = :token " +
           "AND prt.consumed = false AND prt.expiresAt > :now")
    Optional<PasswordResetToken> findValidToken(@Param("token") String token, @Param("now") LocalDateTime now);
    
    /**
     * Find all tokens for a user
     */
    @Query("SELECT prt FROM PasswordResetToken prt WHERE prt.user = :user " +
           "ORDER BY prt.createdAt DESC")
    java.util.List<PasswordResetToken> findByUserOrderByCreatedAtDesc(@Param("user") User user);
    
    /**
     * Delete expired tokens
     */
    @Modifying
    @Query("DELETE FROM PasswordResetToken prt WHERE prt.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
    
    /**
     * Delete all tokens for a user
     */
    @Modifying
    @Query("DELETE FROM PasswordResetToken prt WHERE prt.user = :user")
    void deleteByUser(@Param("user") User user);
    
    /**
     * Mark all user's tokens as consumed
     */
    @Modifying
    @Query("UPDATE PasswordResetToken prt SET prt.consumed = true, prt.consumedAt = :now " +
           "WHERE prt.user = :user AND prt.consumed = false")
    void consumeAllUserTokens(@Param("user") User user, @Param("now") LocalDateTime now);
}
