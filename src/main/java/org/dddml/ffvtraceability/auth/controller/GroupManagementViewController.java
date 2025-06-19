package org.dddml.ffvtraceability.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class GroupManagementViewController {

    @GetMapping({"/auth-srv/group-management", "/group-management"})
    //@PreAuthorize("hasRole('ADMIN')")
    public String groupManagementPage() {
        return "group-management";
    }
} 