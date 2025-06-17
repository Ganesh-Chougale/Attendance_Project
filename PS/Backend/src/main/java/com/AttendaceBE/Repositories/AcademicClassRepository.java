package com.AttendaceBE.Repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.AttendaceBE.Entities.AcademicClass;

@Repository
public interface AcademicClassRepository extends JpaRepository<AcademicClass, Long> {
	
	Optional<AcademicClass> findByNameAndSemesterAndAcademicYear(String name, String semester, String academicYear);

}
