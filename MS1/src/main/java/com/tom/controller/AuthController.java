package com.tom.controller;

import com.tom.dto.UserRegistrationDto;
import com.tom.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

@RestController
@RequestMapping
@Slf4j
public class AuthController {

    private final AuthService authService;
    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/sign-in")
    public ResponseEntity<?> authenticateUser(Authentication authentication, HttpServletResponse response) {
        return ResponseEntity.ok(authService.getJwtTokensAfterAuthentication(authentication, response));
    }

    @PreAuthorize("hasAuthority('SCOPE_REFRESH_TOKEN')")
    @PostMapping("/refresh-token")
    public ResponseEntity<?> getAccessToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return ResponseEntity.ok(authService.getAccessTokenUsingRefreshToken(authorizationHeader));
    }

    @PostMapping(value = "/sign-up",  consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDto userRegistrationDto,
                                          BindingResult bindingResult, HttpServletResponse httpServletResponse) {
        if (bindingResult.hasErrors()) {
            List<String> errorMessage = bindingResult.getAllErrors().stream()
                .map(e -> e.getDefaultMessage())
                .toList();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        return ResponseEntity.ok(authService.registerUser(userRegistrationDto, httpServletResponse));
    }
}
