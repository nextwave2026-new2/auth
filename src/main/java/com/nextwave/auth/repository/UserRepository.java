package com.nextwave.auth.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.nextwave.common.entity.User;

/**
 * User Repository - Data access layer for User entity
 * 
 * Provides CRUD operations and custom queries for User management.
 * 
 * Design Notes:
 * - Uses Spring Data JPA for automatic implementation
 * - Custom queries for business-specific operations
 * - Supports soft delete pattern
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * Find user by email (case-insensitive)
     * Used for authentication
     */
    Optional<User> findByEmailIgnoreCase(String email);
    
    /**
     * Find user by username (case-insensitive)
     * Alternative authentication method
     */
    Optional<User> findByUsernameIgnoreCase(String username);
    
    /**
     * Find active user by email
     * Only returns non-deleted, enabled accounts
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.email) = LOWER(:email) " +
           "AND u.deleted = false AND u.accountEnabled = true")
    Optional<User> findActiveUserByEmail(@Param("email") String email);
    
    /**
     * Check if email exists (case-insensitive)
     * Used for registration validation
     */
    boolean existsByEmailIgnoreCase(String email);
    
    /**
     * Check if username exists (case-insensitive)
     * Used for registration validation
     */
    boolean existsByUsernameIgnoreCase(String username);
    
    /**
     * Find all users by role
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName AND u.deleted = false")
    List<User> findByRoleName(@Param("roleName") String roleName);
    
    /**
     * Find users with failed login attempts greater than threshold
     */
    @Query("SELECT u FROM User u WHERE u.failedLoginAttempts >= :threshold " +
           "AND u.accountLocked = false AND u.deleted = false")
    List<User> findUsersWithFailedLoginAttempts(@Param("threshold") int threshold);
    
    /**
     * Find all active users
     */
    @Query("SELECT u FROM User u WHERE u.deleted = false AND u.accountEnabled = true")
    List<User> findAllActiveUsers();
    
    /**
     * Find users who haven't logged in since specified date
     */
    @Query("SELECT u FROM User u WHERE u.lastLogin < :since AND u.deleted = false")
    List<User> findInactiveUsersSince(@Param("since") LocalDateTime since);
    
    /**
     * Count active users
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.deleted = false AND u.accountEnabled = true")
    long countActiveUsers();
    
    /**
     * Find user by email including deleted accounts
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.email) = LOWER(:email)")
    Optional<User> findByEmailIncludingDeleted(@Param("email") String email);
}
