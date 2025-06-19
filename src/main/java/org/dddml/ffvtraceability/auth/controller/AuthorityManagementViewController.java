package org.dddml.ffvtraceability.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthorityManagementViewController {

    @GetMapping("/authority-management")
    //@PreAuthorize("hasRole('ADMIN')")
    public String authorityManagementPage() {
        return "authority-management";
    }
} 