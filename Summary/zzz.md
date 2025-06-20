PS\Backend\pom.xml:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>3.5.0</version>
		<relativePath/> 
	</parent>
	<groupId>com.AttendaceBE</groupId>
	<artifactId>Backend</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>Backend</name>
	<description>Attendance Project</description>
	<url/>
	<licenses>
		<license/>
	</licenses>
	<developers>
		<developer/>
	</developers>
	<scm>
		<connection/>
		<developerConnection/>
		<tag/>
		<url/>
	</scm>
	<properties>
		<java.version>17</java.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>
		<dependency>
			<groupId>com.mysql</groupId>
			<artifactId>mysql-connector-j</artifactId>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>org.projectlombok</groupId>
			<artifactId>lombok</artifactId>
			<optional>true</optional>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>

		<dependency>
		    <groupId>org.springframework.boot</groupId>
		    <artifactId>spring-boot-starter-security</artifactId>
		    <version>3.3.6</version>
		</dependency>

		<dependency>
		    <groupId>io.jsonwebtoken</groupId>
		    <artifactId>jjwt-api</artifactId>
		    <version>0.12.6</version>
		</dependency>

		<dependency>
		    <groupId>io.jsonwebtoken</groupId>
		    <artifactId>jjwt-impl</artifactId>
		    <version>0.12.6</version>
		    <scope>runtime</scope>
		</dependency>

		<dependency>
		    <groupId>io.jsonwebtoken</groupId>
		    <artifactId>jjwt-jackson</artifactId>
		    <version>0.12.6</version>
		    <scope>runtime</scope>
		</dependency>

		<dependency>
		    <groupId>org.springframework.boot</groupId>
		    <artifactId>spring-boot-starter-validation</artifactId>
		    <version>3.3.3</version>
		</dependency>

		<dependency>
		    <groupId>org.springframework.boot</groupId>
		    <artifactId>spring-boot-starter-actuator</artifactId>
		</dependency>
	</dependencies>

	<build>
		<plugins>
			<plugin>
				<groupId>org.apache.maven.plugins</groupId>
				<artifactId>maven-compiler-plugin</artifactId>
				<configuration>
					<annotationProcessorPaths>
						<path>
							<groupId>org.projectlombok</groupId>
							<artifactId>lombok</artifactId>
						</path>
					</annotationProcessorPaths>
				</configuration>
			</plugin>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<configuration>
					<excludes>
						<exclude>
							<groupId>org.projectlombok</groupId>
							<artifactId>lombok</artifactId>
						</exclude>
					</excludes>
				</configuration>
			</plugin>
		</plugins>
	</build>

</project>
```

PS\Backend\src\main\java\com\AttendaceBE\BackendApplication.java:
```java
package com.AttendaceBE;

import java.util.Date;
import java.util.TimeZone;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import jakarta.annotation.PostConstruct;

@SpringBootApplication
public class BackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}


}
```

PS\Backend\src\main\java\com\AttendaceBE\Config\SecurityConfig.java:
```java
package com.AttendaceBE.Config;

import com.AttendaceBE.Security.JwtAuthenticationFilter;
import com.AttendaceBE.Security.JwtAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity; 
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity; 
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService; 
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity 
@EnableMethodSecurity 
public class SecurityConfig {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsService userDetailsService; 


    public SecurityConfig(JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                          JwtAuthenticationFilter jwtAuthenticationFilter,
                          UserDetailsService userDetailsService) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService); 
        authProvider.setPasswordEncoder(passwordEncoder());     
        return authProvider;
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http:
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); 
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With", "Accept")); 
        configuration.setAllowCredentials(true); 
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); 
        return source;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) 
            .cors(cors -> cors.configurationSource(corsConfigurationSource())) 
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(jwtAuthenticationEntryPoint) 
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) 
            )
            .authorizeHttpRequests(auth -> auth

                .requestMatchers("/api/auth/**").permitAll() 
                .requestMatchers(
                    "/v2/api-docs",        
                    "/v3/api-docs",        
                    "/v3/api-docs/**",     
                    "/swagger-resources",
                    "/swagger-resources/**",
                    "/configuration/ui",
                    "/configuration/security",
                    "/swagger-ui/**",      
                    "/webjars/**",         
                    "/swagger-ui.html"     
                ).permitAll() 
                .requestMatchers("/actuator/**").permitAll() 


                .anyRequest().authenticated()
            )
            .authenticationProvider(authenticationProvider()) 
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); 

        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```

PS\Backend\src\main\java\com\AttendaceBE\Controllers\AdminController.java:
```java
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
@PreAuthorize("hasRole('ADMIN')") 
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }


    @PostMapping("/users")
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody AdminUserCreateRequest request) {
        try {
            UserDto newUser = userService.createUser(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build(); 
        }
    }


    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getAllUsers(@RequestParam Optional<Role> role) {
        List<UserDto> users = userService.getAllUsers(role);
        return ResponseEntity.ok(users);
    }


    @GetMapping("/users/{userId}")
    public ResponseEntity<UserDto> getUserById(@PathVariable Long userId) {
        try {
            UserDto user = userService.getUserById(userId);
            return ResponseEntity.ok(user);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }


    @PutMapping("/users/{userId}")
    public ResponseEntity<UserDto> updateUser(@PathVariable Long userId, @Valid @RequestBody AdminUserUpdateRequest request) {
        try {
            UserDto updatedUser = userService.updateUser(userId, request);
            return ResponseEntity.ok(updatedUser);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build(); 
        }
    }


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
```

PS\Backend\src\main\java\com\AttendaceBE\Controllers\AuthController.java:
```java
package com.AttendaceBE.Controllers;

import com.AttendaceBE.DTOs.AuthenticationRequest;
import com.AttendaceBE.DTOs.AuthenticationResponse;
import com.AttendaceBE.DTOs.RegisterRequest;
import com.AttendaceBE.Services.AuthService;
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
            @RequestBody RegisterRequest request
    ) {
        try {
            AuthenticationResponse response = authService.register(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(AuthenticationResponse.builder().token(e.getMessage()).build());
        } catch (Exception e) {

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(AuthenticationResponse.builder().token("Registration failed: " + e.getMessage()).build());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody AuthenticationRequest request
    ) {
        try {
            AuthenticationResponse response = authService.login(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {


            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthenticationResponse.builder().token("Authentication failed: " + e.getMessage()).build());
        }
    }
}
```

PS\Backend\src\main\java\com\AttendaceBE\Controllers\UserController.java:
```java
package com.AttendaceBE.Controllers;

import com.AttendaceBE.DTOs.UserProfileDto;
import com.AttendaceBE.Entities.User;
import com.AttendaceBE.Services.AuthService; 
import com.AttendaceBE.Services.UserDetailsServiceImpl; 
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
    private final UserDetailsServiceImpl userDetailsService; 

    public UserController(AuthService authService, UserDetailsServiceImpl userDetailsService) {
        this.authService = authService;
        this.userDetailsService = userDetailsService;
    }


    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()") 
    public ResponseEntity<UserProfileDto> getUserProfile() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName(); 


        User user = authService.findUserByUsername(username); 

        UserProfileDto profileDto = UserProfileDto.builder()
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName()) 
                .email(user.getEmail())
                .role(user.getRole())
                .enabled(user.isEnabled())
                .build();

        return ResponseEntity.ok(profileDto);
    }


    @PutMapping("/profile")
    @PreAuthorize("isAuthenticated()") 
    public ResponseEntity<UserProfileDto> updateUserProfile(@RequestBody UserProfileDto profileDto) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();


        if (!username.equals(profileDto.getUsername())) {

            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }


        User updatedUser = authService.updateUserProfile(username, profileDto);

        UserProfileDto updatedProfileDto = UserProfileDto.builder()
                .username(updatedUser.getUsername())
                .firstName(updatedUser.getFirstName())
                .lastName(updatedUser.getLastName()) 
                .email(updatedUser.getEmail())
                .role(updatedUser.getRole()) 
                .enabled(updatedUser.isEnabled()) 
                .build();

        return ResponseEntity.ok(updatedProfileDto);
    }
}
```

PS\Backend\src\main\java\com\AttendaceBE\DatabaseHealthCheck.java:
```java
package com.AttendaceBE;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class DatabaseHealthCheck implements CommandLineRunner {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public void run(String... args) {
        try {

            jdbcTemplate.execute("SELECT 1");
            System.out.println("✅ Successfully connected to the database!");
        } catch (Exception e) {
            System.err.println("❌ Error connecting to the database: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
```

PS\Backend\src\main\java\com\AttendaceBE\DTOs\AdminUserCreateRequest.java:
```java
package com.AttendaceBE.DTOs;

import com.AttendaceBE.Enums.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AdminUserCreateRequest {

    @NotBlank(message = "Username cannot be empty")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "Password cannot be empty")
    @Size(min = 6, message = "Password must be at least 6 characters long")
    private String password;

    @NotBlank(message = "First name cannot be empty")
    private String firstName;

    @NotBlank(message = "Last name cannot be empty")
    private String lastName;

    @NotBlank(message = "Email cannot be empty")
    @Email(message = "Invalid email format")
    private String email;

    @NotNull(message = "Role cannot be null")
    private Role role; 
}
```

PS\Backend\src\main\java\com\AttendaceBE\DTOs\AdminUserUpdateRequest.java:
```java
package com.AttendaceBE.DTOs;

import com.AttendaceBE.Enums.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AdminUserUpdateRequest {

    @NotBlank(message = "First name cannot be empty")
    private String firstName;

    @NotBlank(message = "Last name cannot be empty")
    private String lastName;

    @NotBlank(message = "Email cannot be empty")
    @Email(message = "Invalid email format")
    private String email;

    private Role role; 
    private Boolean enabled; 
}
```

PS\Backend\src\main\java\com\AttendaceBE\DTOs\AuthenticationRequest.java:
```java
package com.AttendaceBE.DTOs;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {
    private String username;
    private String password;
}
```

PS\Backend\src\main\java\com\AttendaceBE\DTOs\AuthenticationResponse.java:
```java
package com.AttendaceBE.DTOs;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    private String token;


}
```

PS\Backend\src\main\java\com\AttendaceBE\DTOs\RegisterRequest.java:
```java
package com.AttendaceBE.DTOs;

import com.AttendaceBE.Enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data 
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String username;
    private String password;
    private String firstName;
    private String lastName; 
    private String email;
    private Role role; 


}
```

PS\Backend\src\main\java\com\AttendaceBE\DTOs\UserDto.java:
```java
package com.AttendaceBE.DTOs;

import com.AttendaceBE.Enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
    private Long id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private Role role;
    private boolean enabled;
}
```

PS\Backend\src\main\java\com\AttendaceBE\DTOs\UserProfileDto.java:
```java
package com.AttendaceBE.DTOs;

import com.AttendaceBE.Enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileDto {
    private String username;
    private String firstName;
    private String lastName; 
    private String email;
    private Role role; 
    private boolean enabled; 
}
```

PS\Backend\src\main\java\com\AttendaceBE\Entities\AcademicClass.java:
```java
package com.AttendaceBE.Entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "classes")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AcademicClass extends BaseEntity {

	@Column(nullable = false, unique = true)
	private String name;

	 @Column(nullable = false)
	 private String semester;

	 @Column(name = "academic_year", nullable = false)
	 private String academicYear;

}
```

PS\Backend\src\main\java\com\AttendaceBE\Entities\Attendance.java:
```java
package com.AttendaceBE.Entities;

import java.time.LocalDateTime;

import com.AttendaceBE.Enums.AttendanceStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "attendance")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Attendance extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "student_id", nullable = false)
    private User student; 

    @ManyToOne
    @JoinColumn(name = "lecture_id", nullable = false)
    private Lecture lecture; 

    @Column(name = "mark_time", nullable = false)
    private LocalDateTime markTime;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private AttendanceStatus status; 
}
```

PS\Backend\src\main\java\com\AttendaceBE\Entities\BaseEntity.java:
```java
package com.AttendaceBE.Entities;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import lombok.Getter;
import lombok.Setter;

@MappedSuperclass
@Getter
@Setter
public class BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

}
```

PS\Backend\src\main\java\com\AttendaceBE\Entities\Lecture.java:
```java
package com.AttendaceBE.Entities;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "lectures")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Lecture extends BaseEntity {

    @Column(name = "lecture_date_time", nullable = false)
    private LocalDateTime lectureDateTime;

    @ManyToOne
    @JoinColumn(name = "teacher_id", nullable = false)
    private User teacher; 

    @ManyToOne
    @JoinColumn(name = "subject_id", nullable = false)
    private Subject subject; 

    @ManyToOne
    @JoinColumn(name = "class_id", nullable = false)
    private AcademicClass assignedClass; 

    @Column(name = "qr_code")
    private String qrCode; 

    @Column(name = "qr_code_expiration")
    private LocalDateTime qrCodeExpiration; 

    @Column(name = "is_active", nullable = false)
    private boolean isActive = false; 
}
```

PS\Backend\src\main\java\com\AttendaceBE\Entities\Subject.java:
```java
package com.AttendaceBE.Entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "subjects")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Subject extends BaseEntity {

    @Column(nullable = false, unique = true)
    private String name;

    @Column(nullable = false, unique = true)
    private String code;

}
```

PS\Backend\src\main\java\com\AttendaceBE\Entities\TeacherClassSubject.java:
```java
package com.AttendaceBE.Entities;

import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "teacher_class_subjects")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TeacherClassSubject extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "teacher_id", nullable = false)
    private User teacher; 

    @ManyToOne
    @JoinColumn(name = "class_id", nullable = false)
    private AcademicClass assignedClass; 

    @ManyToOne
    @JoinColumn(name = "subject_id", nullable = false)
    private Subject subject;
}
```

PS\Backend\src\main\java\com\AttendaceBE\Entities\User.java:
```java
package com.AttendaceBE.Entities;

import com.AttendaceBE.Enums.Role;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User extends BaseEntity {

	@Column(nullable = false, unique = true)
	private String username;

	@Column(nullable = false)
	private String password;

	@Column(name = "first_name")
	private String firstName;

	@Column(name = "last_name")
	private String lastName;

	@Column(nullable = false, unique = true)
	private String email;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	private Role role;

	@Column(nullable = false)
	private boolean enabled = true;

}
```

PS\Backend\src\main\java\com\AttendaceBE\Enums\AttendanceStatus.java:
```java
package com.AttendaceBE.Enums;

public enum AttendanceStatus {
    PRESENT,
    ABSENT
}
```

PS\Backend\src\main\java\com\AttendaceBE\Enums\Role.java:
```java
package com.AttendaceBE.Enums;

public enum Role {
    ADMIN,
    TEACHER,
    STUDENT
}
```

PS\Backend\src\main\java\com\AttendaceBE\Repositories\AcademicClassRepository.java:
```java
package com.AttendaceBE.Repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.AttendaceBE.Entities.AcademicClass;

@Repository
public interface AcademicClassRepository extends JpaRepository<AcademicClass, Long> {

	Optional<AcademicClass> findByNameAndSemesterAndAcademicYear(String name, String semester, String academicYear);

}
```

PS\Backend\src\main\java\com\AttendaceBE\Repositories\AttendanceRepository.java:
```java
package com.AttendaceBE.Repositories;

import com.AttendaceBE.Entities.Attendance;
import com.AttendaceBE.Entities.Lecture;
import com.AttendaceBE.Entities.User;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AttendanceRepository extends JpaRepository<Attendance, Long> {

    Optional<Attendance> findByStudentAndLecture(User student, Lecture lecture);
    List<Attendance> findByLecture(Lecture lecture);
    List<Attendance> findByStudent(User student);
}
```

PS\Backend\src\main\java\com\AttendaceBE\Repositories\LectureRepository.java:
```java
package com.AttendaceBE.Repositories;

import com.AttendaceBE.Entities.Lecture;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LectureRepository extends JpaRepository<Lecture, Long> {

    Optional<Lecture> findByQrCodeAndIsActiveTrue(String qrCode);


}
```

PS\Backend\src\main\java\com\AttendaceBE\Repositories\SubjectRepository.java:
```java
package com.AttendaceBE.Repositories;

import com.AttendaceBE.Entities.Subject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SubjectRepository extends JpaRepository<Subject, Long> {

}
```

PS\Backend\src\main\java\com\AttendaceBE\Repositories\TeacherClassSubjectRepository.java:
```java
package com.AttendaceBE.Repositories;

import com.AttendaceBE.Entities.TeacherClassSubject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TeacherClassSubjectRepository extends JpaRepository<TeacherClassSubject, Long> {
}
```

PS\Backend\src\main\java\com\AttendaceBE\Repositories\UserRepository.java:
```java
package com.AttendaceBE.Repositories;

import com.AttendaceBE.Entities.User;
import com.AttendaceBE.Enums.Role; 
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List; 
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);


    List<User> findByRole(Role role);
}
```

PS\Backend\src\main\java\com\AttendaceBE\Security\JwtAuthenticationEntryPoint.java:
```java
package com.AttendaceBE.Security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: " + authException.getMessage());
    }
}
```

PS\Backend\src\main\java\com\AttendaceBE\Security\JwtAuthenticationFilter.java:
```java
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


        logger.debug("Filter Chain Start: Request URI = {}", request.getRequestURI());
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            logger.debug("Filter Chain Start: Authentication already present: {}", SecurityContextHolder.getContext().getAuthentication().getName());
        } else {
            logger.debug("Filter Chain Start: No authentication present.");
        }


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
                System.out.println("--- JwtAuthenticationFilter: SecurityContextHolder set! --- Current Auth: " + SecurityContextHolder.getContext().getAuthentication()); 
            } else {
                logger.warn("JWT token is not valid for user '{}' according to JwtService.isTokenValid().", username);
            }
        } else if (username == null) {
            logger.debug("Username extracted from token was null after parsing. This should be caught by earlier blocks.");
        } else {
            logger.debug("SecurityContextHolder already contains authentication for user. Skipping authentication filter for this request.");
        }

        filterChain.doFilter(request, response);


        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            logger.debug("Filter Chain End: Authentication present for: {}", SecurityContextHolder.getContext().getAuthentication().getName());
        } else {
            logger.debug("Filter Chain End: No authentication present.");
        }

    }
}
```

PS\Backend\src\main\java\com\AttendaceBE\Security\JwtService.java:
```java
package com.AttendaceBE.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.ExpiredJwtException; 
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token); 
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(
            UserDetails userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {


            final String username = extractUsername(token); 

            final Date expiration = extractExpiration(token);
            final Date now = new Date();

            System.out.println("DEBUG (JwtService.isTokenValid): Token Extracted Username: " + username);
            System.out.println("DEBUG (JwtService.isTokenValid): UserDetails Username: " + userDetails.getUsername());
            System.out.println("DEBUG (JwtService.isTokenValid): Token Expiration: " + expiration);
            System.out.println("DEBUG (JwtService.isTokenValid): Current Time: " + now);
            System.out.println("DEBUG (JwtService.isTokenValid): Is token expired? " + expiration.before(now));
            System.out.println("DEBUG (JwtService.isTokenValid): Is username match? " + (username.equals(userDetails.getUsername())));

            return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        } catch (SignatureException e) {

            System.err.println("ERROR (JwtService.isTokenValid): Invalid JWT signature! (This should be caught earlier if filter is working)");
            System.err.println("Exception details: " + e.getMessage());
            e.printStackTrace();
            return false;
        } catch (ExpiredJwtException e) { 
            System.err.println("ERROR (JwtService.isTokenValid): JWT has expired! (This should be caught earlier if filter is working)");
            System.err.println("Exception details: " + e.getMessage());
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            System.err.println("ERROR (JwtService.isTokenValid): Generic error validating token: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {


        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
```

PS\Backend\src\main\java\com\AttendaceBE\Services\AuthService.java:
```java
package com.AttendaceBE.Services;

import com.AttendaceBE.DTOs.AuthenticationRequest;
import com.AttendaceBE.DTOs.AuthenticationResponse;
import com.AttendaceBE.DTOs.RegisterRequest;
import com.AttendaceBE.DTOs.UserProfileDto; 
import com.AttendaceBE.Entities.User;
import com.AttendaceBE.Enums.Role;
import com.AttendaceBE.Repositories.UserRepository;
import com.AttendaceBE.Security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Collections;


@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsServiceImpl userDetailsService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       AuthenticationManager authenticationManager,
                       UserDetailsServiceImpl userDetailsService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    public AuthenticationResponse register(RegisterRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already taken.");
        }
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already registered.");
        }

        Role assignedRole = request.getRole() != null ? request.getRole() : Role.STUDENT;

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName()) 
                .email(request.getEmail())
                .role(assignedRole)
                .enabled(true)
                .build();

        userRepository.save(user);

        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                true,
                true,
                true,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );
        var jwtToken = jwtService.generateToken(userDetails);

        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        final UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        var jwtToken = jwtService.generateToken(userDetails);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }


    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }


    public User updateUserProfile(String username, UserProfileDto profileDto) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));


        if (profileDto.getFirstName() != null) {
            user.setFirstName(profileDto.getFirstName());
        }
        if (profileDto.getLastName() != null) {
            user.setLastName(profileDto.getLastName()); 
        }

        if (profileDto.getEmail() != null && !profileDto.getEmail().equals(user.getEmail())) {
            if (userRepository.findByEmail(profileDto.getEmail()).isPresent()) {
                throw new IllegalArgumentException("Email " + profileDto.getEmail() + " is already taken by another user.");
            }
            user.setEmail(profileDto.getEmail());
        }


        return userRepository.save(user);
    }
}
```

PS\Backend\src\main\java\com\AttendaceBE\Services\UserDetailsServiceImpl.java:
```java
package com.AttendaceBE.Services;

import com.AttendaceBE.Repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList; 
import org.springframework.security.core.authority.SimpleGrantedAuthority; 

import java.util.Collections;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.AttendaceBE.Entities.User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));


        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(), 
                true, 
                true, 
                true, 

                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );
    }
}
```

PS\Backend\src\main\java\com\AttendaceBE\Services\UserService.java:
```java
package com.AttendaceBE.Services;

import com.AttendaceBE.DTOs.AdminUserCreateRequest;
import com.AttendaceBE.DTOs.AdminUserUpdateRequest;
import com.AttendaceBE.DTOs.UserDto;
import com.AttendaceBE.Entities.User;
import com.AttendaceBE.Enums.Role;
import com.AttendaceBE.Repositories.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public UserDto createUser(AdminUserCreateRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already taken: " + request.getUsername());
        }
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already registered: " + request.getEmail());
        }

        User newUser = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .role(request.getRole()) 
                .enabled(true)
                .build();

        User savedUser = userRepository.save(newUser);
        return mapUserToUserDto(savedUser);
    }

    @Transactional(readOnly = true)
    public List<UserDto> getAllUsers(Optional<Role> role) {
        List<User> users;
        if (role.isPresent()) {
            users = userRepository.findByRole(role.get());
        } else {
            users = userRepository.findAll();
        }
        return users.stream()
                .map(this::mapUserToUserDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public UserDto getUserById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));
        return mapUserToUserDto(user);
    }

    @Transactional
    public UserDto updateUser(Long userId, AdminUserUpdateRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }
        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }

        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.findByEmail(request.getEmail()).isPresent()) {
                throw new IllegalArgumentException("Email " + request.getEmail() + " is already taken by another user.");
            }
            user.setEmail(request.getEmail());
        }

        if (request.getRole() != null) {
            user.setRole(request.getRole());
        }
        if (request.getEnabled() != null) {
            user.setEnabled(request.getEnabled());
        }

        User updatedUser = userRepository.save(user);
        return mapUserToUserDto(updatedUser);
    }

    @Transactional
    public void deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

        user.setEnabled(false);
        userRepository.save(user);


    }


    private UserDto mapUserToUserDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .role(user.getRole())
                .enabled(user.isEnabled())
                .build();
    }
}
```

PS\Backend\src\main\resources\application.properties:
```properties
spring.application.name=Backend
spring.datasource.url=jdbc:mysql://localhost:3306/AttendanceDB
spring.datasource.username=root
spring.datasource.password=root
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQLDialect
server.port=8080

management.endpoints.web.exposure.include=health
management.endpoint.health.show-details=always

logging.pattern.console=%clr(%5p) %t --- %logger{36} --- %clr(%m) %n
logging.level.org.springframework.security=DEBUG
logging.level.io.jsonwebtoken=DEBUG

# JWT Configuration
application.security.jwt.secret-key=Rm9vYmFyMTIzQCRUcmFuc3BhcmVudExvbmdLZXlGb3JKV1RzZXJ2aWNlS2V5MTIzNDU2Nzg5MA==
application.security.jwt.expiration=604800000
# 7 days in milliseconds (7 * 24 * 60 * 60 * 1000) - Set this to match refresh token for simplicity, or longer if needed
application.security.jwt.refresh-token.expiration=604800000
# 7 days in milliseconds (7 * 24 * 60 * 60 * 1000)
```

