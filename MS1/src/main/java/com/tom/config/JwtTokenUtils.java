package com.tom.config;

import com.tom.config.userConfig.UserInfoConfig;
import com.tom.repo.UserInfoRepo;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Objects;

@Component
public class JwtTokenUtils {

    private final UserInfoRepo userInfoRepo;

    // Constructor to initialize userInfoRepo
    public JwtTokenUtils(UserInfoRepo userInfoRepo) {
        this.userInfoRepo = userInfoRepo;
    }

    public String getUserName(Jwt jwtToken) {
        return jwtToken.getSubject();
    }

    public boolean isTokenValid(Jwt jwtToken, UserDetails userDetails) {
        final String userName = getUserName(jwtToken);
        boolean isTokenExpired = getIfTokenIsExpired(jwtToken);
        boolean isTokenUserSameAsDatabase = userName.equals(userDetails.getUsername());
        return !isTokenExpired && isTokenUserSameAsDatabase;
    }

    private boolean getIfTokenIsExpired(Jwt jwtToken) {
        return Objects.requireNonNull(jwtToken.getExpiresAt()).isBefore(Instant.now());
    }

    public UserDetails userDetails(String emailId) {
        return userInfoRepo
            .findByEmailId(emailId)
            .map(UserInfoConfig::new)
            .orElseThrow(() -> new UsernameNotFoundException("UserEmail: " + emailId + " does not exist"));
    }
}
