package ru.kata.spring.boot_security.demo.service;





import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repositories.UserRepository;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


@Service
public class UserServiceImpl implements UserService, UserDetailsService {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    @Autowired
    @Lazy
    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }




    public User findByUsername(String username){
        return userRepository.findByUsername(username);
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(String.format("User '%s' not found " ,username));
        }



        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                user.getPassword(),  mapRolesToAuthorities(user.getRoles()));
    }


    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public void save(User user) {
        // Если пароль не начинается с BCrypt-префикса, хешируем его
        if (user.getPassword() == null || !user.getPassword().startsWith("$2a$")) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        userRepository.save(user);
    }



    @Override
    public User findById(Long id) {
        return userRepository.findById(id).orElse(null);

    }

    @Override
    public List<User> findAll() {
        return userRepository.findAll();

    }

//    @Override
//    public void update(Long id, User user) {
//
//               user.setPassword(passwordEncoder.encode(user.getPassword()));
//        userRepository.save(user);
//    }


    //ЭТО Я ДОБАВИЛ ПЕРЕД СНОМ
@Override
@Transactional
public void update(Long id, User updatedUser) {
    // 1. Получаем текущего пользователя
    User existingUser = userRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

    // 2. Определяем, менялся ли username
    boolean usernameChanged = false;
    if (updatedUser.getUsername() != null && !updatedUser.getUsername().equals(existingUser.getUsername())) {
        existingUser.setUsername(updatedUser.getUsername());
        usernameChanged = true;
    }

    // 3. Обязательно обновляем lastName (без условия)
    if (updatedUser.getLastName() != null) {
        existingUser.setLastName(updatedUser.getLastName());
    }

    // 4. Безопасное обновление пароля
    if (updatedUser.getPassword() != null && !updatedUser.getPassword().isEmpty()) {
        if (passwordEncoder.matches(updatedUser.getPassword(), existingUser.getPassword())) {
            throw new IllegalArgumentException("New password must differ from current password");
        }
        existingUser.setPassword(passwordEncoder.encode(updatedUser.getPassword()));
    }

    // 5. Обновление ролей
    if (updatedUser.getRoles() != null) {
        existingUser.setRoles(updatedUser.getRoles());
    }

    // 6. Сохраняем изменения
    userRepository.save(existingUser);

    // 7. Обновление контекста безопасности (особенно важно при смене username)
    updateSecurityContext(existingUser, usernameChanged);
}

    private void updateSecurityContext(User user, boolean credentialsChanged) {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        if (currentAuth != null && currentAuth.getName().equals(user.getUsername())) {
            UserDetails userDetails = this.loadUserByUsername(user.getUsername());

            // Создаем новый объект аутентификации
            Authentication newAuth = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    credentialsChanged ? userDetails.getPassword() : currentAuth.getCredentials(),
                    userDetails.getAuthorities()
            );

            SecurityContextHolder.getContext().setAuthentication(newAuth);
        }
    }//ЭТО Я ДОБАВИЛ ПЕРЕД СНОМ^^^^^^^^^^выше





    //ЭТО И ТАК РАБОТАЛО , ЭТОТ МЕТОД В ПРИОРИТЕТЕ ПОКА
//    @Override
//    @Transactional
//    public void update(Long id, User updatedUser) {
//        User existingUser = userRepository.findById(id)
//                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));
//
//        if (updatedUser.getUsername() != null && !updatedUser.getUsername().equals(existingUser.getUsername())) {
//            existingUser.setUsername(updatedUser.getUsername());
//        }
//
//        if (updatedUser.getLastName() != null && !updatedUser.getLastName().equals(existingUser.getLastName())) {
//            existingUser.setLastName(updatedUser.getLastName());
//        }
//
//        if (updatedUser.getPassword() != null && !updatedUser.getPassword().isEmpty()) {
//            if (passwordEncoder.matches(updatedUser.getPassword(), existingUser.getPassword())) {
//                throw new IllegalArgumentException("New password must differ from current password");
//            }
//            existingUser.setPassword(passwordEncoder.encode(updatedUser.getPassword()));
//        }
//
//        if (updatedUser.getRoles() != null && !updatedUser.getRoles().isEmpty()) {
//            existingUser.setRoles(updatedUser.getRoles());
//        }
//
//        userRepository.save(existingUser);
//
//        // Обновление контекста безопасности
//        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
//        if (currentAuth != null && currentAuth.getName().equals(existingUser.getUsername())) {
//            UserDetails userDetails = this.loadUserByUsername(existingUser.getUsername());
//            Authentication newAuth = new UsernamePasswordAuthenticationToken(
//                    userDetails,
//                    userDetails.getUsername(),
//                    userDetails.getAuthorities()
//            );
//            SecurityContextHolder.getContext().setAuthentication(newAuth);
//        }
//    }
    //ЭТО И ТАК РАБОТАЛО , ЭТОТ МЕТОД В ПРИОРИТЕТЕ ПОКА^^^^^^^^^выше

    @Override
    public void delete(Long id) {
        userRepository.deleteById(id);

    }

}





