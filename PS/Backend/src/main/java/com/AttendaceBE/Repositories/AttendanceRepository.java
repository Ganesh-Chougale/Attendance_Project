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