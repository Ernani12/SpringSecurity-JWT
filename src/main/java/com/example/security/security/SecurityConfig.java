package com.example.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class SecurityConfig {
    

    @Bean
    public InMemoryUserDetailsManager userDetailsManager() {
        return new InMemoryUserDetailsManager(
                org.springframework.security.core.userdetails.User
                        .withUsername("cliente")
                        .password(passwordEncoder().encode("cliente123"))
                        .roles("CLIENTE")
                        .build(),
                org.springframework.security.core.userdetails.User
                        .withUsername("gerente")
                        .password(passwordEncoder().encode("gerente123"))
                        .roles("GERENTE")
                        .build()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()) // Desabilita CSRF (apenas para simplificação inicial)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/css/**", "/js/**").permitAll() // Libera login e recursos estáticos
                .requestMatchers("/gerente/**").hasRole("GERENTE") // Rotas para gerente
                .requestMatchers("/cliente/**").hasRole("CLIENTE") // Rotas para cliente
                .anyRequest().authenticated() // Outras rotas exigem autenticação
            )
            .formLogin(login -> login
                .loginPage("/login") // Define a página personalizada de login
                .successHandler(authenticationSuccessHandler()) // Redireciona com base na role
                .permitAll() // Permite acesso público ao login
            )
            .logout(logout -> logout.permitAll()); // Permite logout sem autenticação
    
        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, org.springframework.security.core.Authentication authentication) -> {
            String role = authentication.getAuthorities().stream()
                    .findFirst()
                    .map(Object::toString)
                    .orElse("");

            if (role.equals("ROLE_CLIENTE")) {
                response.sendRedirect("/cliente/home");
            } else if (role.equals("ROLE_GERENTE")) {
                response.sendRedirect("/gerente/home");
            } else {
                response.sendRedirect("/default");
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
  
   
}
