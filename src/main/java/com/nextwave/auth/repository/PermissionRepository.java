package com.nextwave.auth.repository;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.nextwave.common.entity.Permission;

/**
 * Permission Repository - Data access layer for Permission entity
 * 
 * Provides CRUD operations and custom queries for Permission management.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    
    /**
     * Find permission by name
     */
    Optional<Permission> findByName(String name);
    
    /**
     * Check if permission exists by name
     */
    boolean existsByName(String name);
    
    /**
     * Find permissions by resource
     */
    Set<Permission> findByResource(String resource);
    
    /**
     * Find permissions by role ID
     */
    @Query("SELECT p FROM Permission p JOIN p.roles r WHERE r.id = :roleId")
    Set<Permission> findByRoleId(@Param("roleId") Long roleId);
    
    /**
     * Find permissions by user ID (through roles)
     */
    @Query("SELECT DISTINCT p FROM Permission p " +
           "JOIN p.roles r " +
           "JOIN r.users u " +
           "WHERE u.id = :userId")
    Set<Permission> findByUserId(@Param("userId") Long userId);
}
