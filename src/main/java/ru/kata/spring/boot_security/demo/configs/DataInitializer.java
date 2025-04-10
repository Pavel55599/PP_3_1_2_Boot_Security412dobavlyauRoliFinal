package ru.kata.spring.boot_security.demo.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;

import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repositories.RoleRepository;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.util.Set;

@Component
public class DataInitializer  {

    @Bean
    public CommandLineRunner initUsers(UserService userService,
                                       PasswordEncoder passwordEncoder,
                                       RoleRepository roleRepository) {
        return args -> {
            // Создаем роли, если их нет

            Role adminRole = createRoleIfNotExists("ROLE_ADMIN", roleRepository);
            Role userRole = createRoleIfNotExists("ROLE_USER", roleRepository);

            // Создаем администратора
            createUserIfNotExists(
                    "admin",
                    "admin",  // пароль будет закодирован
                    "Adminov",
                    Set.of(adminRole, userRole),  // админ может иметь и роль пользователя
                    userService,
                    passwordEncoder
            );

            // Создаем обычного пользователя
            createUserIfNotExists(
                    "user",
                    "user",  // пароль будет закодирован
                    "Userov",
                    Set.of(userRole),
                    userService,
                    passwordEncoder
            );
        };
    }

    private Role createRoleIfNotExists(String roleName, RoleRepository roleRepository) {
        Role role = roleRepository.findByName(roleName);
        if (role == null) {
            role = new Role(roleName);
            roleRepository.save(role);
        }
        return role;
    }

    private void createUserIfNotExists(String username,
                                       String password,
                                       String lastName,
                                       Set<Role> roles,
                                       UserService userService,
                                       PasswordEncoder passwordEncoder) {
        if (userService.findByUsername(username) == null) {
            User user = new User();
            user.setUsername(username);
            user.setPassword(passwordEncoder.encode(password));  // кодируем пароль
            user.setLastName(lastName);
            user.setEnabled(true);
            user.setRoles(roles);
            userService.save(user);
        }
    }

}




