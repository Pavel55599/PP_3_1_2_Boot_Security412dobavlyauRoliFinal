package ru.kata.spring.boot_security.demo.controller;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin")
public class AdminController {
    private final UserService userService;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AdminController(UserService userService, RoleService roleService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public String adminPanel(Model model) {
        model.addAttribute("users", userService.findAll());
            return "admin/indexlist";

    }


    @GetMapping("/show")
    public String showUser(@RequestParam("id") Long id, Model model) {
        model.addAttribute("user", userService.findById(id));
        return "admin/show";
    }


        @GetMapping("/new")
    public String newUser(Model model) {
        model.addAttribute("user", new User());

        model.addAttribute("allRoles", roleService.getAllRoles());
        return "admin/new";
    }

    @PostMapping
    public String createUser(@ModelAttribute("user") User user,
                             @RequestParam(value = "selectedRoles", required = false) Set<Long> selectedRoles) {
        Set<Role> roles = new HashSet<>();
        if (selectedRoles != null) {
            for (Long roleId : selectedRoles) {
                roles.add(roleService.getRoleById(roleId));
            }
        }
        user.setRoles(roles);
        userService.save(user);
        return "redirect:/admin";
    }



    @GetMapping("/edit")
    public String editUser(@RequestParam("id") Long id, Model model) {
        model.addAttribute("user", userService.findById(id));
        model.addAttribute("allRoles", roleService.getAllRoles());

        return "admin/edit";
    }




    @PostMapping("/update")
    public String updateUser(@RequestParam("id") Long id,
                             @ModelAttribute("user") User user,
    @RequestParam(value = "selectedRoles", required = false) List <Long> roleIds) {


        if (roleIds != null) {
            Set<Role> roles = roleIds.stream().map(roleService::getRoleById).collect(Collectors.toSet());
            user.setRoles(roles);
            userService.save(user);
        }

        userService.update(id, user);
        return "redirect:/admin";
    }






    @GetMapping("/delete")
    public String showDeleteForm(@RequestParam("id") Long id, Model model) {
        model.addAttribute("user", userService.findById(id));
        return "admin/delete";
    }

    @PostMapping("/delete")
    public String deleteUser(@RequestParam("id") Long id) {
        userService.delete(id);
        return "redirect:/admin";
    }
}



