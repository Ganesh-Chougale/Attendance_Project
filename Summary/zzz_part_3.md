
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

