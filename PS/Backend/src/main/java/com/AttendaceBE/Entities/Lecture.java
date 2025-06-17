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