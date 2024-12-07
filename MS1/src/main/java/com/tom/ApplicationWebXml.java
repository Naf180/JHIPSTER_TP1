package com.tom;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import tech.jhipster.config.DefaultProfileUtil;
public class ApplicationWebXml extends SpringBootServletInitializer {
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        DefaultProfileUtil.addDefaultProfile(application.application());
        return application.sources(Ms1App.class);
    }
}
