package com.tom.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class HelloController {
    @GetMapping("/hello")
   public ResponseEntity<String> SayHello() {
        return ResponseEntity.ok("Bonjour je te dis hellow");
    }
}
