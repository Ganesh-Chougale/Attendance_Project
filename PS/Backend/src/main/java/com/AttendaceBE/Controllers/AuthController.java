package com.AttendaceBE.Controllers;

import com.AttendaceBE.DTOs.AuthenticationRequest;
import com.AttendaceBE.DTOs.AuthenticationResponse;
import com.AttendaceBE.DTOs.RegisterRequest;
import com.AttendaceBE.Services.AuthService;
import jakarta.validation.Valid; // Assuming you might add @Valid to RegisterRequest/AuthenticationRequest later
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @Valid @RequestBody RegisterRequest request // Added @Valid, make sure DTO has validation annotations
    ) {
        // Removed try-catch.
        // IllegalArgumentException (username/email already exists) will be handled by GlobalExceptionHandler
        // and return 400 Bad Request with specific message.
        // MethodArgumentNotValidException (@Valid issues) will also be handled globally.
        AuthenticationResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody AuthenticationRequest request
    ) {
        // Removed try-catch.
        // BadCredentialsException (wrong password) will be handled by GlobalExceptionHandler,
        // returning 401 Unauthorized with "Invalid username or password".
        // UsernameNotFoundException (user not found) will be handled by GlobalExceptionHandler,
        // returning 404 Not Found (or 401, depending on how you want to expose user existence).
        AuthenticationResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }
}