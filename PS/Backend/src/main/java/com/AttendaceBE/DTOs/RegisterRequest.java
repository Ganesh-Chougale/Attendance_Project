package com.AttendaceBE.DTOs;

import com.AttendaceBE.Enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // Combines @Getter, @Setter, @ToString, @EqualsAndHashCode
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String username;
    private String password;
    private String firstName;
    private String lastName; 
    private String email;
    private Role role; // You might want to control this on the backend for student self-registration
                       // or restrict it to ADMIN only for setting roles other than STUDENT.
                       // For student self-registration, this might be hardcoded to STUDENT in the service.
}