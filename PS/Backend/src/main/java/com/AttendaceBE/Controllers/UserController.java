package com.AttendaceBE.Controllers;

import com.AttendaceBE.DTOs.UserProfileDto;
import com.AttendaceBE.Entities.User;
import com.AttendaceBE.Services.AuthService; // We'll add profile logic here
import com.AttendaceBE.Services.UserDetailsServiceImpl; // To load UserDetails
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final AuthService authService;
    private final UserDetailsServiceImpl userDetailsService; // To fetch the actual User entity

    public UserController(AuthService authService, UserDetailsServiceImpl userDetailsService) {
        this.authService = authService;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Retrieves the profile of the authenticated user.
     * Accessible by any authenticated user.
     * @return UserProfileDto representing the current user's profile.
     */
    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()") // Ensures only authenticated users can access
    public ResponseEntity<UserProfileDto> getUserProfile() {
        // Get the authenticated user's username from the SecurityContext
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName(); // This is the principal's username

        // Load the full UserDetails from your UserDetailsService
        // Note: userDetailsService.loadUserByUsername returns Spring Security's UserDetails.
        // We need to get back to our custom User entity if we want all its fields (like first/last name).
        // This typically involves having a way to get the full entity from the username.
        // For simplicity, we'll fetch from repository here, or you could extend UserDetailsImpl
        // to hold your full User entity.

        User user = authService.findUserByUsername(username); // New method in AuthService

        UserProfileDto profileDto = UserProfileDto.builder()
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName()) // Using getLasName() to match your entity
                .email(user.getEmail())
                .role(user.getRole())
                .enabled(user.isEnabled())
                .build();

        return ResponseEntity.ok(profileDto);
    }

    /**
     * Updates the profile of the authenticated user.
     * Accessible by any authenticated user.
     * @param profileDto UserProfileDto containing the updated profile information.
     * @return UserProfileDto with the updated profile.
     */
    @PutMapping("/profile")
    @PreAuthorize("isAuthenticated()") // Ensures only authenticated users can access
    public ResponseEntity<UserProfileDto> updateUserProfile(@RequestBody UserProfileDto profileDto) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        // Ensure the user is only updating their own profile
        if (!username.equals(profileDto.getUsername())) {
            // Or throw an exception if you want to be stricter
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        // Call AuthService to handle the update logic
        User updatedUser = authService.updateUserProfile(username, profileDto);

        UserProfileDto updatedProfileDto = UserProfileDto.builder()
                .username(updatedUser.getUsername())
                .firstName(updatedUser.getFirstName())
                .lastName(updatedUser.getLastName()) // Using getLasName() to match your entity
                .email(updatedUser.getEmail())
                .role(updatedUser.getRole()) // Role typically not updated via this endpoint
                .enabled(updatedUser.isEnabled()) // Enabled status typically not updated via this endpoint
                .build();

        return ResponseEntity.ok(updatedProfileDto);
    }
}