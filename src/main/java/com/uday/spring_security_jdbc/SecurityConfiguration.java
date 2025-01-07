package com.uday.spring_security_jdbc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecurityConfiguration {

    @Autowired
    private final DataSource dataSource;

    public SecurityConfiguration(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Disable CSRF (if not needed)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin").hasRole("ADMIN") // Only ADMIN role can access /admin/**
                        .requestMatchers("/user").hasAnyRole("USER", "ADMIN")   // Only USER role can access /user/**
                        .requestMatchers("/**").permitAll()     // Everyone can access /public/**
                        .anyRequest().authenticated()                  // All other requests require authentication
                )
                .formLogin(form -> form.defaultSuccessUrl("/", true)) // Form-based login with default success URL
                .httpBasic(basic -> {}); // Enable HTTP Basic authentication

        return http.build();
    }

    @Bean
    public UserDetailsManager userDetailsManager() {
        // Use JdbcUserDetailsManager to fetch user details from the database
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);

        // Optionally, customize the default queries if your table structure differs
        manager.setUsersByUsernameQuery("SELECT username, password, enabled FROM users WHERE username = ?");
        manager.setAuthoritiesByUsernameQuery("SELECT username, authority FROM authorities WHERE username = ?");

        return manager;
    }
}
