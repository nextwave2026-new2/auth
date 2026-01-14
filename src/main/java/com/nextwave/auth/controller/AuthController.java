package com.nextwave.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    @GetMapping("/")
    public String hello() {
        return "Hello auth service! Tui là Duc handsome - Auto deploy working!";
    }
}
