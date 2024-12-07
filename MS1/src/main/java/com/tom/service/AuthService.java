package com.tom.service;

import com.tom.config.JwtTokenGenerator;
import com.tom.dto.AuthResponseDto;
import com.tom.dto.TokenType;
import com.tom.dto.UserRegistrationDto;
import com.tom.Entity.RefreshTokenEntity;
import com.tom.Entity.UserInfoEntity;
import com.tom.mapper.UserInfoMapper;
import com.tom.repo.RefreshTokenRepo;
import com.tom.repo.UserInfoRepo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.util.Arrays;
import java.util.Optional;
@Service
public class AuthService {
    private final UserInfoRepo userInfoRepo;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final RefreshTokenRepo refreshTokenRepo;
    private final UserInfoMapper userInfoMapper;
    //@Autowired
    //private  PasswordEncoder passwordEncoder;
    @Autowired
    public AuthService(UserInfoRepo userInfoRepo, JwtTokenGenerator jwtTokenGenerator,
                       RefreshTokenRepo refreshTokenRepo, UserInfoMapper userInfoMapper) {
        this.userInfoRepo = userInfoRepo;
      //  this.passwordEncoder = passwordEncoder;
        this.jwtTokenGenerator = jwtTokenGenerator;
        this.refreshTokenRepo = refreshTokenRepo;
        this.userInfoMapper = userInfoMapper;
    }

    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response) {
        try {
            var userInfoEntity = userInfoRepo.findByEmailId(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND"));
            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);
            saveUserRefreshToken(userInfoEntity, refreshToken);
            createRefreshTokenCookie(response, refreshToken);
            return AuthResponseDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(15 * 60)
                .userName(userInfoEntity.getUserName())
                .tokenType(TokenType.Bearer)
                .build();
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
        }
    }
    private Cookie createRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60); // in seconds
        response.addCookie(refreshTokenCookie);
        return refreshTokenCookie;
    }
    private void saveUserRefreshToken(UserInfoEntity userInfoEntity, String refreshToken) {
        // Utilisation du Builder personnalisé
        RefreshTokenEntity refreshTokenEntity = new RefreshTokenEntity.Builder()
            .setUser(userInfoEntity)
            .setRefreshToken(refreshToken)
            .setRevoked(false)
            .build();
        // Sauvegarde de l'entité dans le repository
        refreshTokenRepo.save(refreshTokenEntity);
    }
    public Object getAccessTokenUsingRefreshToken(String authorizationHeader) {
        if (!authorizationHeader.startsWith(TokenType.Bearer.name())) {
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please verify your token type");
        }
        final String refreshToken = authorizationHeader.substring(7);
        var refreshTokenEntity = refreshTokenRepo.findByRefreshToken(refreshToken)
            .filter(tokens -> !tokens.isRevoked())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh token revoked"));
        UserInfoEntity userInfoEntity = refreshTokenEntity.getUser();
        Authentication authentication = createAuthenticationObject(userInfoEntity);
        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
        return AuthResponseDto.builder()
            .accessToken(accessToken)
            .accessTokenExpiry(5 * 60)
            .userName(userInfoEntity.getUserName())
            .tokenType(TokenType.Bearer)
            .build();
    }
    private  Authentication createAuthenticationObject(UserInfoEntity userInfoEntity) {
        String username = userInfoEntity.getEmailId();
        String password = userInfoEntity.getPassword();
       // String encodedPassword = passwordEncoder.encode(password);
        String roles = userInfoEntity.getRoles();

        String[] roleArray = roles.split(",");
        GrantedAuthority[] authorities = Arrays.stream(roleArray)
            .map(role -> (GrantedAuthority) role::trim)
            .toArray(GrantedAuthority[]::new);
        return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
    }

    public AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto, HttpServletResponse httpServletResponse) {
        try {
            Optional<UserInfoEntity> user = userInfoRepo.findByEmailId(userRegistrationDto.userEmail());
            if (user.isPresent()) {
                throw new Exception("User Already Exists");
            }

            UserInfoEntity userDetailsEntity = userInfoMapper.convertToEntity(userRegistrationDto);
            userDetailsEntity.setPassword(userRegistrationDto.userPassword());
            Authentication authentication = createAuthenticationObject(userDetailsEntity);
            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);
            UserInfoEntity savedUserDetails = userInfoRepo.save(userDetailsEntity);
            saveUserRefreshToken(userDetailsEntity, refreshToken);
            return AuthResponseDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60)
                .userName(savedUserDetails.getUserName())
                .tokenType(TokenType.Bearer)
                .build();
       } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }
}
