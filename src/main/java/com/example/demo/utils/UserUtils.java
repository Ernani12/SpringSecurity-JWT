

package com.example.demo.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class UserUtils {

    // Retorna o nome do usuário atualmente autenticado
    public static String getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) authentication.getPrincipal()).getUsername();
        }
        return null;
    }

    // Verifica se o usuário é um gerente
    public static boolean isGerente() {
        return hasRole("ROLE_GERENTE");
    }

    // Verifica se o usuário é um cliente
    public static boolean isCliente() {
        return hasRole("ROLE_CLIENTE");
    }

    // Verifica se o usuário possui um papel específico
    private static boolean hasRole(String role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getAuthorities() != null) {
            Collection<?> authorities = authentication.getAuthorities();
            return authorities.stream().anyMatch(auth -> auth.toString().equals(role));
        }
        return false;
    }
}
