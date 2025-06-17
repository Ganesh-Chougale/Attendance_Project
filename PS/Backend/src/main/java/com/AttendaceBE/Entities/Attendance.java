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