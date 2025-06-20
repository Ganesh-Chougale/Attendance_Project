package com.AttendaceBE.Repositories;

import com.AttendaceBE.Entities.User;
import com.AttendaceBE.Enums.Role; // Import Role enum
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List; // Import List
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    // Added for admin user listing with role filter
    List<User> findByRole(Role role);
}