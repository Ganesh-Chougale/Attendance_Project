package com.AttendaceBE.Repositories;

import com.AttendaceBE.Entities.TeacherClassSubject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TeacherClassSubjectRepository extends JpaRepository<TeacherClassSubject, Long> {
}