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
        // Removed try-catch.
        // IllegalArgumentException (username/email taken) will be handled by GlobalExceptionHandler
        // and return a 400 Bad Request with details.
        // MethodArgumentNotValidException (@Valid issues) will also be handled globally.
        UserDto newUser = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
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
        // Removed try-catch.
        // IllegalArgumentException (user not found) will be handled by GlobalExceptionHandler
        // and return a 404 Not Found with details.
        UserDto user = userService.getUserById(userId);
        return ResponseEntity.ok(user);
    }

    // PUT /api/admin/users/{userId} - Admin updates user details
    @PutMapping("/users/{userId}")
    public ResponseEntity<UserDto> updateUser(@PathVariable Long userId, @Valid @RequestBody AdminUserUpdateRequest request) {
        // Removed try-catch.
        // IllegalArgumentException (user not found, email taken) will be handled by GlobalExceptionHandler.
        // MethodArgumentNotValidException (@Valid issues) will also be handled globally.
        UserDto updatedUser = userService.updateUser(userId, request);
        return ResponseEntity.ok(updatedUser);
    }

    // DELETE /api/admin/users/{userId} - Admin "soft deletes" a user by disabling them
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        // Removed try-catch.
        // IllegalArgumentException (user not found) will be handled by GlobalExceptionHandler
        // and return a 404 Not Found with details.
        userService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }
}