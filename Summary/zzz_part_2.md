
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