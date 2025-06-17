PS\Backend\src\main\java\com\AttendaceBE\BackendApplication.java:
```java
package com.AttendaceBE;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
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

PS\Backend\src\main\java\com\AttendaceBE\Entities\Subject.java:
```java
package com.AttendaceBE.Entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Entity
@Table(name = "subjects")
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
    private Class assignedClass; 

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
	private String lasName;

	@Column(nullable = false, unique = true)
	private String email;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	private Role role;

	@Column(nullable = false)
	private boolean enabled = true;

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
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository 
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

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
```

