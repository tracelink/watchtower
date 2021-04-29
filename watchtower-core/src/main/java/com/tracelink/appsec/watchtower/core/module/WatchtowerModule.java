package com.tracelink.appsec.watchtower.core.module;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The module annotation, used in conjunction with the {@link AbstractModule}.
 * <p>
 * This annotation enables a Spring component scan, JPA configuration, and
 * Entity Discovery
 *
 * @author mcool
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@ComponentScan
@EnableJpaRepositories
@EntityScan
public @interface WatchtowerModule {

}
