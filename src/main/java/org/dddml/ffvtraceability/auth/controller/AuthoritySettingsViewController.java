package org.dddml.ffvtraceability.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthoritySettingsViewController {

    @GetMapping("/authority-settings")
    //@PreAuthorize("hasRole('ADMIN')")
    public String authoritySettingsPage() {
        return "authority-settings";
    }
} 