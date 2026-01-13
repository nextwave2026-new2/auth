package com.nextwave.auth.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.nextwave.common.entity.RefreshToken;
import com.nextwave.common.entity.User;

/**
 * RefreshToken Repository - Data access layer for RefreshToken entity
 * 
 * Manages refresh tokens for JWT authentication.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    /**
     * Find refresh token by token string
     */
    Optional<RefreshToken> findByToken(String token);
    
    /**
     * Find all valid tokens for a user
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user " +
           "AND rt.revoked = false AND rt.expiresAt > :now")
    List<RefreshToken> findValidTokensByUser(@Param("user") User user, @Param("now") LocalDateTime now);
    
    /**
     * Find all tokens for a user
     */
    List<RefreshToken> findByUser(User user);
    
    /**
     * Delete expired tokens
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
    
    /**
     * Delete all tokens for a user
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.user = :user")
    void deleteByUser(@Param("user") User user);
    
    /**
     * Revoke all tokens for a user
     */
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.user = :user")
    void revokeAllUserTokens(@Param("user") User user);
    
    /**
     * Count valid tokens for a user
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user = :user " +
           "AND rt.revoked = false AND rt.expiresAt > :now")
    long countValidTokensByUser(@Param("user") User user, @Param("now") LocalDateTime now);
}
