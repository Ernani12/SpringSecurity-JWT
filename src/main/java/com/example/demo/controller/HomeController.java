package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.example.demo.utils.UserUtils;



@Controller
public class HomeController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/default")
    public String redirectUserBasedOnRole() {
        return "redirect:" + (UserUtils.isGerente() ? "/gerente/welcome" : "/cliente/welcome");
    }

    @GetMapping("/gerente/welcome")
    public String gerentePage(Model model) {
        model.addAttribute("user", UserUtils.getCurrentUser());
        return "gerente/welcome";
    }

    @GetMapping("/cliente/welcome")
    public String clientePage(Model model) {
        model.addAttribute("user", UserUtils.getCurrentUser());
        return "cliente/welcome";
    }
}
