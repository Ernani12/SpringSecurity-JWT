package com.example.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/")
    public String home() {
        return "login";
    }
    

    @GetMapping("/default")
    public String defaultAfterLogin(Authentication authentication) {
        if (authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_GERENTE"))) {
            return "redirect:/gerente/home";
        } else {
            return "redirect:/cliente/home";
        }
    }

    @GetMapping("/gerente/home")
    public String gerenteHome() {
        return "gerente-home";
    }

    @GetMapping("/cliente/home")
    public String clienteHome() {
        return "cliente-home";
    }
}
