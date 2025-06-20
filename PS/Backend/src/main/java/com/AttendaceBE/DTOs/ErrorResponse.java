package com.AttendaceBE.DTOs;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL) // Only include non-null fields in JSON output
public class ErrorResponse {
    private LocalDateTime timestamp;
    private int status;
    private String error; // E.g., "Bad Request", "Unauthorized", "Not Found"
    private String message; // A general message describing the error
    private String path; // The request URI
    private Map<String, String> fieldErrors; // For validation errors (field -> message)
    private List<String> details; // For other specific details or multiple errors
}