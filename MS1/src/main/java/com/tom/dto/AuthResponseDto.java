package com.tom.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthResponseDto {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("access_token_expiry")
    private int accessTokenExpiry;

    @JsonProperty("token_type")
    private TokenType tokenType;

    @JsonProperty("user_name")
    private String userName;

    // Constructeur privé pour le Builder
    private AuthResponseDto(Builder builder) {
        this.accessToken = builder.accessToken;
        this.accessTokenExpiry = builder.accessTokenExpiry;
        this.tokenType = builder.tokenType;
        this.userName = builder.userName;
    }

    // Getters et Setters
    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public int getAccessTokenExpiry() {
        return accessTokenExpiry;
    }

    public void setAccessTokenExpiry(int accessTokenExpiry) {
        this.accessTokenExpiry = accessTokenExpiry;
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public void setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    // Méthode builder statique
    public static Builder builder() {
        return new Builder();
    }

    // Classe interne Builder
    public static class Builder {
        private String accessToken;
        private int accessTokenExpiry;
        private TokenType tokenType;
        private String userName;

        public Builder accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public Builder accessTokenExpiry(int accessTokenExpiry) {
            this.accessTokenExpiry = accessTokenExpiry;
            return this;
        }

        public Builder tokenType(TokenType tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public Builder userName(String userName) {
            this.userName = userName;
            return this;
        }

        public AuthResponseDto build() {
            return new AuthResponseDto(this);
        }
    }
}
