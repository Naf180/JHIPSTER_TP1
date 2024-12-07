package com.tom.Entity;

import jakarta.persistence.*;
import java.util.List;

@Entity
@Table(name = "USER_INFO")
public class UserInfoEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "USER_NAME")
    private String userName;

    @Column(nullable = false, name = "EMAIL_ID", unique = true)
    private String emailId;

    @Column(nullable = false, name = "PASSWORD")
    private String password;

    @Column(name = "MOBILE_NUMBER")
    private String mobileNumber;

    @Column(nullable = false, name = "ROLES")
    private String roles;

    // Association OneToMany avec RefreshTokenEntity
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private List<RefreshTokenEntity> refreshTokens;

    // Constructeur par défaut
    public UserInfoEntity() {}

    public UserInfoEntity(String userName, String emailId, String password, String roles) {
            this.userName = userName;
        this.emailId = emailId;
        this.password = password;
        this.roles = roles;
    }

    // Getters et Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getEmailId() {
        return emailId;
    }

    public void setEmailId(String emailId) {
        this.emailId = emailId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getMobileNumber() {
        return mobileNumber;
    }

    public void setMobileNumber(String mobileNumber) {
        this.mobileNumber = mobileNumber;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public List<RefreshTokenEntity> getRefreshTokens() {
        return refreshTokens;
    }

    public void setRefreshTokens(List<RefreshTokenEntity> refreshTokens) {
        this.refreshTokens = refreshTokens;
    }
}
