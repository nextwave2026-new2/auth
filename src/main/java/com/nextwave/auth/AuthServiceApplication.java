package com.nextwave.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;

import com.nextwave.common.util.EnvLoader;

@SpringBootApplication
@EntityScan(basePackages = "com.nextwave.common.entity")
public class AuthServiceApplication {
    // Load .env file before Spring starts
    static {
        EnvLoader.load();
    }
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
