package com.tom.config.userConfig;

import com.tom.Entity.UserInfoEntity;
import com.tom.repo.UserInfoRepo;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class InitialUserInfo implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(InitialUserInfo.class);

    private final UserInfoRepo userInfoRepo;
    //private final PasswordEncoder passwordEncoder;

    // Constructor injection
    public InitialUserInfo(UserInfoRepo userInfoRepo) {
        this.userInfoRepo = userInfoRepo;
        //this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        UserInfoEntity manager = new UserInfoEntity();
        manager.setUserName("Manager");
        manager.setPassword("password");
        manager.setRoles("ROLE_MANAGER");
        manager.setEmailId("manager@manager.com");

        UserInfoEntity admin = new UserInfoEntity();
        admin.setUserName("Admin");
        admin.setPassword("password");
        admin.setRoles("ROLE_ADMIN");
        admin.setEmailId("admin@admin.com");

        UserInfoEntity user = new UserInfoEntity();
        user.setUserName("User");
        user.setPassword("password");
        user.setRoles("ROLE_USER");
        user.setEmailId("user@user.com");

        // Uncomment this line to save the users
        // userInfoRepo.saveAll(List.of(manager, admin, user));

        // Optionally log information for debugging
        log.info("Initial users created: Manager, Admin, and User.");
    }
}
