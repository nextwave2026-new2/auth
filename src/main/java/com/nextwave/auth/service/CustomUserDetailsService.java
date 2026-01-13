package com.nextwave.auth.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.nextwave.auth.repository.UserRepository;
import com.nextwave.auth.security.UserPrincipal;
import com.nextwave.common.entity.User;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Custom UserDetailsService Implementation
 * 
 * Loads user-specific data for Spring Security authentication.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    /**
     * Load user by username or email
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        log.debug("Loading user by username or email: {}", usernameOrEmail);
        
        User user = userRepository.findByUsernameIgnoreCase(usernameOrEmail)
                .or(() -> userRepository.findByEmailIgnoreCase(usernameOrEmail))
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found with username or email: " + usernameOrEmail
                ));
        
        if (user.getDeleted()) {
            throw new UsernameNotFoundException("User account has been deleted");
        }
        
        return UserPrincipal.create(user);
    }
    
    /**
     * Load user by ID
     */
    @Transactional(readOnly = true)
    public UserDetails loadUserById(Long id) {
        log.debug("Loading user by ID: {}", id);
        
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));
        
        if (user.getDeleted()) {
            throw new UsernameNotFoundException("User account has been deleted");
        }
        
        return UserPrincipal.create(user);
    }
}
