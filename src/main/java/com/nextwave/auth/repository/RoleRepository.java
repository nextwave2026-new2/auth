package com.nextwave.auth.repository;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.nextwave.common.entity.Role;

/**
 * Role Repository - Data access layer for Role entity
 * 
 * Provides CRUD operations and custom queries for Role management.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    
    /**
     * Find role by name
     */
    Optional<Role> findByName(String name);
    
    /**
     * Check if role exists by name
     */
    boolean existsByName(String name);
    
    /**
     * Find roles by user ID
     */
    @Query("SELECT r FROM Role r JOIN r.users u WHERE u.id = :userId")
    Set<Role> findByUserId(@Param("userId") Long userId);
    
    /**
     * Find roles with specific permission
     */
    @Query("SELECT r FROM Role r JOIN r.permissions p WHERE p.name = :permissionName")
    Set<Role> findByPermissionName(@Param("permissionName") String permissionName);
}
