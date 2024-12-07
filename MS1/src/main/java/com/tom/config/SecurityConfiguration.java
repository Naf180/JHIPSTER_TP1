package com.tom.config;

import com.tom.config.JwtAccessTokenFilter;
import com.tom.config.JwtRefreshTokenFilter;
import com.tom.config.JwtTokenUtils;
import com.tom.config.userConfig.UserInfoManagerConfig;
import com.tom.repo.RefreshTokenRepo;
import com.tom.service.LogoutHandlerService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    private final UserInfoManagerConfig userInfoManagerConfig;
    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepo refreshTokenRepo;
    private final LogoutHandlerService logoutHandlerService;

    public SecurityConfiguration(UserInfoManagerConfig userInfoManagerConfig,
                                 RSAKeyRecord rsaKeyRecord,
                                 JwtTokenUtils jwtTokenUtils,
                                 RefreshTokenRepo refreshTokenRepo,
                                 LogoutHandlerService logoutHandlerService) {
        this.userInfoManagerConfig = userInfoManagerConfig;
        this.rsaKeyRecord = rsaKeyRecord;
        this.jwtTokenUtils = jwtTokenUtils;
        this.refreshTokenRepo = refreshTokenRepo;
        this.logoutHandlerService = logoutHandlerService;
    }

    @Order(1)
    @Bean
    public SecurityFilterChain signInSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
            .securityMatcher(new AntPathRequestMatcher("/sign-in/**"))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .userDetailsService(userInfoManagerConfig)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> {
                ex.authenticationEntryPoint((request, response, authException) ->
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
            })
            .formLogin(withDefaults())
            .httpBasic(withDefaults())
            .build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
            .securityMatcher(new AntPathRequestMatcher("/api/**"))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
            .addFilterBefore(new JwtAccessTokenFilter(rsaKeyRecord, jwtTokenUtils), UsernamePasswordAuthenticationFilter.class)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> {
                ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
            })
            .formLogin(withDefaults())
            .httpBasic(withDefaults())
            .build();
    }

    @Order(3)
    @Bean
    public SecurityFilterChain refreshTokenSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
            .securityMatcher(new AntPathRequestMatcher("/refresh-token/**"))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> {
                ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
            })
            .httpBasic(withDefaults())
            .build();
    }

    @Order(4)
    @Bean
    public SecurityFilterChain logoutSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
            .securityMatcher(new AntPathRequestMatcher("/logout/**"))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(new JwtAccessTokenFilter(rsaKeyRecord, jwtTokenUtils), UsernamePasswordAuthenticationFilter.class)
            .logout(logout -> logout
                .logoutUrl("/logout")
                .addLogoutHandler(logoutHandlerService)
                .logoutSuccessHandler(((request, response, authentication) -> SecurityContextHolder.clearContext()))
            )
            .exceptionHandling(ex -> {
                ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
            })
            .build();
    }

    @Order(5)
    @Bean
    public SecurityFilterChain registerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
            // Applique un filtre uniquement aux requêtes "/sign-up/**"
            .securityMatcher(new AntPathRequestMatcher("/sign-up/**"))
            .csrf(AbstractHttpConfigurer::disable) // Désactive la protection CSRF pour cette route spécifique
            .authorizeRequests(auth ->
                auth.anyRequest().permitAll())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // Indique que la session est sans état (stateless)
            .build();
    }

    //@Bean
    //public PasswordEncoder passwordEncoder() {
      //  return new BCryptPasswordEncoder();
    //}

   /* @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
    }
    @Bean
    JwtEncoder jwtEncoder(){
        JWK jwk = new RSAKey.Builder(rsaKeyRecord.rsaPublicKey()).privateKey(rsaKeyRecord.rsaPrivateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }*/

}
