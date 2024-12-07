package com.tom.Entity;

import jakarta.persistence.*;

@Entity
@Table(name = "REFRESH_TOKENS")
public class RefreshTokenEntity {

    @Id
    @GeneratedValue
    private Long id;

    // Augmenter la longueur pour que cela puisse contenir la longueur du token réel
    @Column(name = "REFRESH_TOKEN", nullable = false, length = 10000)
    private String refreshToken;

    @Column(name = "REVOKED")
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private UserInfoEntity user;

    // Constructeur par défaut
    public RefreshTokenEntity() {}

    // Constructeur avec paramètres
    public RefreshTokenEntity(Long id, String refreshToken, boolean revoked, UserInfoEntity user) {
        this.id = id;
        this.refreshToken = refreshToken;
        this.revoked = revoked;
        this.user = user;
    }

    // Getters et Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public UserInfoEntity getUser() {
        return user;
    }

    public void setUser(UserInfoEntity user) {
        this.user = user;
    }

    // Builder pattern
    public static class Builder {
        private Long id;
        private String refreshToken;
        private boolean revoked;
        private UserInfoEntity user;

        public Builder setId(Long id) {
            this.id = id;
            return this;
        }

        public Builder setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public Builder setRevoked(boolean revoked) {
            this.revoked = revoked;
            return this;
        }

        public Builder setUser(UserInfoEntity user) {
            this.user = user;
            return this;
        }

        // La méthode build() crée une instance de RefreshTokenEntity
        public RefreshTokenEntity build() {
            RefreshTokenEntity entity = new RefreshTokenEntity();
            entity.setId(this.id);
            entity.setRefreshToken(this.refreshToken);
            entity.setRevoked(this.revoked);
            entity.setUser(this.user);
            return entity;
        }
    }
}
