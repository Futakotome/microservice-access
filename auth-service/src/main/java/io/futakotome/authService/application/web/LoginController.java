package io.futakotome.authService.application.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    @GetMapping(value = "/login.html")
    public String loginPage() {
        return "login";
    }
}
