package com.dundermifflin.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/index.html", "/swagger-ui/**", "/v3/api-docs/**", "/actuator/**", "/openapi/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/dundermifflin").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        // Read access for inventory and catalogs to USER and ADMIN
                        .requestMatchers(HttpMethod.GET, "/api/v1/dundermifflin/inventory/**", "/api/v1/dundermifflin/catalogs/**", "/api/v1/dundermifflin/inventario/**", "/api/v1/dundermifflin/catalogos/**").hasAnyRole("USER", "ADMIN")
                        // Mutations restricted to ADMIN
                        .requestMatchers(HttpMethod.POST, "/api/v1/dundermifflin/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/v1/dundermifflin/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/api/v1/dundermifflin/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/dundermifflin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public UserDetailsService users(PasswordEncoder encoder) {
        UserDetails user = User.withUsername("user")
                .password(encoder.encode("user123"))
                .roles("USER")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password(encoder.encode("admin123"))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
