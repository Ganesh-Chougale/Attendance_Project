package com.AttendaceBE.Security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // --- ADDED DEBUGGING ---
        logger.debug("Filter Chain Start: Request URI = {}", request.getRequestURI());
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            logger.debug("Filter Chain Start: Authentication already present: {}", SecurityContextHolder.getContext().getAuthentication().getName());
        } else {
            logger.debug("Filter Chain Start: No authentication present.");
        }
        // --- END ADDED DEBUGGING ---

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        String username = null;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.debug("No JWT token found in request or not a Bearer token. Continuing filter chain.");
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);

        try {
            username = jwtService.extractUsername(jwt);
            logger.debug("Successfully extracted username '{}' from JWT.", username);
        } catch (SignatureException ex) {
            logger.error("JWT validation failed: Invalid JWT signature for token: {}", jwt, ex);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Unauthorized: Invalid JWT Signature.");
            return;
        } catch (ExpiredJwtException ex) {
            logger.error("JWT validation failed: Token has expired for token: {}", jwt, ex);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Unauthorized: Token has expired.");
            return;
        } catch (Exception ex) {
            logger.error("JWT validation failed: General JWT parsing error for token: {}", jwt, ex);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Unauthorized: Invalid Token Format or Content.");
            return;
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails;
            try {
                userDetails = this.userDetailsService.loadUserByUsername(username);
                logger.debug("User details loaded from database for username: {}", username);
            } catch (Exception e) {
                logger.error("Error loading user details for username: {}. User might not exist or be disabled.", username, e);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Unauthorized: User not found or invalid credentials.");
                return;
            }

            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);
                logger.debug("Authentication successful for user: {}. SecurityContextHolder updated.", username);
                System.out.println("--- JwtAuthenticationFilter: SecurityContextHolder set! --- Current Auth: " + SecurityContextHolder.getContext().getAuthentication()); // SUPER CRUCIAL TEST LINE
            } else {
                logger.warn("JWT token is not valid for user '{}' according to JwtService.isTokenValid().", username);
            }
        } else if (username == null) {
            logger.debug("Username extracted from token was null after parsing. This should be caught by earlier blocks.");
        } else {
            logger.debug("SecurityContextHolder already contains authentication for user. Skipping authentication filter for this request.");
        }

        filterChain.doFilter(request, response);

        // --- ADDED DEBUGGING ---
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            logger.debug("Filter Chain End: Authentication present for: {}", SecurityContextHolder.getContext().getAuthentication().getName());
        } else {
            logger.debug("Filter Chain End: No authentication present.");
        }
        // --- END ADDED DEBUGGING ---
    }
}