package com.AttendaceBE;

import java.util.Date;
import java.util.TimeZone;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import jakarta.annotation.PostConstruct;

@SpringBootApplication
public class BackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}
	
//	@PostConstruct
//	public void init() {
//	    TimeZone.setDefault(TimeZone.getTimeZone("Asia/Kolkata"));
//	    System.out.println("Spring Boot Application Timezone: " + TimeZone.getDefault().getID());
//	    System.out.println("Current Server Time (for verification): " + new Date());
//	}
}
