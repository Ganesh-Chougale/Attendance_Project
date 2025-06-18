package com.AttendaceBE.DTOs;

import com.AttendaceBE.Enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// Using @Data for getters, setters, equals, hashCode, toString
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileDto {
    private String username;
    private String firstName;
    private String lastName; // Corrected from lasName for consistency in DTOs
    private String email;
    private Role role; // Role might be read-only for users, but good to include for GET
    private boolean enabled; // Read-only for users
}