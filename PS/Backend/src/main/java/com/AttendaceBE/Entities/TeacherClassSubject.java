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