package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.security.Principal;


@Controller
@RequestMapping("/user")
public class UserController {
    private final UserService userService;
    private final RoleService roleService;

    @Autowired
    public UserController(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping
    public String userPanel(Principal principal, Model model) {
        User currentUser = userService.findByUsername(principal.getName());
        if (currentUser == null) {
            return "redirect:/login?error=user_not_found";
        }
        model.addAttribute("user", currentUser);
        model.addAttribute("allRoles", roleService.getAllRoles());
        return "user/personal";
    }

    @GetMapping("/showuser")
    public String showUser(@RequestParam("id") Long id,
                           Principal principal,
                           Model model) {
        User currentUser = userService.findByUsername(principal.getName());

        if (currentUser == null || !currentUser.getId().equals(id)) {
            return "redirect:/user?error=access_denied";
        }

        model.addAttribute("user", currentUser);
        model.addAttribute("allRoles", roleService.getAllRoles());
        return "user/showuser";
    }
}






