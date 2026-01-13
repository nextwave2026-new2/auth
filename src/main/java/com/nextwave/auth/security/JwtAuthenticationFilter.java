package com.nextwave.auth.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT Authentication Filter
 * 
 * Intercepts incoming requests and validates JWT tokens.
 * If valid, sets the authentication in SecurityContext.
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            log.debug("Processing request: {} {}", request.getMethod(), request.getRequestURI());
            
            String jwt = getJwtFromRequest(request);
            
            if (jwt == null) {
                log.debug("No JWT token found in request");
            } else {
                log.debug("JWT token found, validating...");
            }
            
            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
                String username = jwtTokenProvider.getUsernameFromToken(jwt);
                
                log.debug("JWT token is valid for user: {}", username);
                
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                log.debug("Set authentication for user: {}", username);
            } else if (StringUtils.hasText(jwt)) {
                log.warn("JWT token validation failed");
            }
        } catch (Exception ex) {
            log.error("Could not set user authentication in security context", ex);
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extract JWT from Authorization header
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        
        log.debug("Authorization header: {}", bearerToken != null ? "Bearer ***" : "null");
        
        if (StringUtils.hasText(bearerToken)) {
            if (bearerToken.startsWith("Bearer ")) {
                String token = bearerToken.substring(7);
                log.debug("Extracted JWT token (length: {})", token.length());
                return token;
            } else {
                log.debug("Authorization header does not start with 'Bearer '");
            }
        }
        
        log.debug("No valid Bearer token found in Authorization header");
        return null;
    }
}
