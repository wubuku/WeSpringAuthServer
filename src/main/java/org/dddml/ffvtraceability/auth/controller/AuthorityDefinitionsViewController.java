package org.dddml.ffvtraceability.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthorityDefinitionsViewController {

    @GetMapping("/authority-settings")
    public String authorityDefinitionsPage() {
        return "authority-settings";
    }
}
