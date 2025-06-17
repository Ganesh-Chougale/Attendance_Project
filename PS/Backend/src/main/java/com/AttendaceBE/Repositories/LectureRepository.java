package com.AttendaceBE.Repositories;

import com.AttendaceBE.Entities.Lecture;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LectureRepository extends JpaRepository<Lecture, Long> {

    Optional<Lecture> findByQrCodeAndIsActiveTrue(String qrCode);

    // Find all active lectures for a specific teacher, subject, or class
    // List<Lecture> findByTeacherAndIsActiveTrue(User teacher);
    // List<Lecture> findByAssignedClassAndIsActiveTrue(Class assignedClass);
}