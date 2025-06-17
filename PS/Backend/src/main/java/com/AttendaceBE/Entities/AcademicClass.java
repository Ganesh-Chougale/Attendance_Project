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
