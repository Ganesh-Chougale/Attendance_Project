package com.AttendaceBE.Controllers;

import com.AttendaceBE.DTOs.AdminUserCreateRequest;
import com.AttendaceBE.DTOs.AdminUserUpdateRequest;
import com.AttendaceBE.DTOs.UserDto;
import com.AttendaceBE.Enums.Role;
import com.AttendaceBE.Services.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')") // All methods in this controller require ADMIN role
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    // POST /api/admin/users - Admin creates a new user (including teachers/students)
    @PostMapping("/users")
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody AdminUserCreateRequest request) {
        try {
            UserDto newUser = userService.createUser(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build(); // Or return a more specific error DTO
        }
    }

    // GET /api/admin/users - Admin gets all users, with optional role filtering
    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getAllUsers(@RequestParam Optional<Role> role) {
        List<UserDto> users = userService.getAllUsers(role);
        return ResponseEntity.ok(users);
    }

    // GET /api/admin/users/{userId} - Admin gets a specific user by ID
    @GetMapping("/users/{userId}")
    public ResponseEntity<UserDto> getUserById(@PathVariable Long userId) {
        try {
            UserDto user = userService.getUserById(userId);
            return ResponseEntity.ok(user);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }

    // PUT /api/admin/users/{userId} - Admin updates user details
    @PutMapping("/users/{userId}")
    public ResponseEntity<UserDto> updateUser(@PathVariable Long userId, @Valid @RequestBody AdminUserUpdateRequest request) {
        try {
            UserDto updatedUser = userService.updateUser(userId, request);
            return ResponseEntity.ok(updatedUser);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build(); // Or return 404 if user not found, 400 for bad data
        }
    }

    // DELETE /api/admin/users/{userId} - Admin "soft deletes" a user by disabling them
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        try {
            userService.deleteUser(userId);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }
}