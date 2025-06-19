package org.dddml.ffvtraceability.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PreRegisterViewController {

    @GetMapping({"/pre-register", "/auth-srv/pre-register"})
    //@PreAuthorize("hasRole('ADMIN')")
    public String preRegisterPage() {
        return "pre-register";
    }
} 