package com.tom;

import com.tom.config.AsyncSyncConfiguration;
import com.tom.config.EmbeddedSQL;
import com.tom.config.JacksonConfiguration;
import com.tom.config.TestSecurityConfiguration;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Base composite annotation for integration tests.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootTest(classes = { Ms2App.class, JacksonConfiguration.class, AsyncSyncConfiguration.class, TestSecurityConfiguration.class })
@EmbeddedSQL
public @interface IntegrationTest {
}
