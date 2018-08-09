package com.example.spring.server.controller;

import com.example.spring.server.exception.ResourceNotFoundException;
import com.example.spring.server.model.ApplicationUser;
import com.example.spring.server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserController(UserRepository applicationUserRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = applicationUserRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @PostMapping(path="/register", produces=MediaType.APPLICATION_JSON_VALUE)
    //@CrossOrigin(origins = "http://localhost:3000")
    public Map<String, Object> register(@Valid @RequestBody ApplicationUser applicationUserRequest) {
        HashMap<String, Object> response = new HashMap<>();
        if(applicationUserRequest.getUsername() != null && applicationUserRequest.getEmail() != null && applicationUserRequest.getPassword() != null) {
            ApplicationUser applicationUser = userRepository.findByUsername(applicationUserRequest.getUsername());
            if (applicationUser == null) {
                applicationUser = userRepository.findByEmail(applicationUserRequest.getEmail());
                if (applicationUser == null) {
                    applicationUserRequest.setPassword(bCryptPasswordEncoder.encode(applicationUserRequest.getPassword()));
                    ApplicationUser createdApplicationUser = userRepository.save(applicationUserRequest);
                    if(createdApplicationUser != null) {
                        response.put("message", "ApplicationUser successfully created");
                        return response;
                    } else {
                        response.put("error", "Internal Server Error");
                        return response;
                    }
                } else {
                    response.put("error", "ApplicationUser with this email already exists");
                    return response;
                }
            } else {
                response.put("error", "ApplicationUser with this username already exists");
                return response;
            }
        } else {
            response.put("error", "Invalid request");
            return response;
        }
    }

    @PostMapping(path="/signin", produces=MediaType.APPLICATION_JSON_VALUE)
    //@CrossOrigin(origins = "http://localhost:3000")
    public Map<String, Object> signin(@Valid @RequestBody ApplicationUser applicationUserRequest) {
        HashMap<String, Object> response = new HashMap<>();
        if(applicationUserRequest.getUsername() != null && applicationUserRequest.getPassword() != null) {
            ApplicationUser applicationUser = userRepository.findByUsername(applicationUserRequest.getUsername());
            if (applicationUser != null) {
                applicationUser = userRepository.findByEmail(applicationUserRequest.getEmail());
                if (applicationUser == null) {
                    String hashedPassword = BCrypt.hashpw(applicationUserRequest.getPassword(), BCrypt.gensalt(10));
                    applicationUserRequest.setPassword(hashedPassword);
                    ApplicationUser createdApplicationUser = userRepository.save(applicationUserRequest);
                    if(createdApplicationUser != null) {
                        response.put("message", "ApplicationUser successfully created");
                        return response;
                    } else {
                        response.put("error", "Internal Server Error");
                        return response;
                    }
                } else {
                    response.put("error", "ApplicationUser with this email already exists");
                    return response;
                }
            } else {
                response.put("error", "Invalid username or password");
                return response;
            }
        } else {
            response.put("error", "Invalid request");
            return response;
        }
    }

    @GetMapping("/user/{userId}")
    //@CrossOrigin(origins = "http://localhost:3000")
    public ApplicationUser getUserById(@PathVariable Long userId) {
        return userRepository.getOne(userId);
    }

    @PutMapping("/user/{userId}")
    //@CrossOrigin(origins = "http://localhost:3000")
    public ApplicationUser updateUser(@PathVariable Long userId, @Valid @RequestBody ApplicationUser applicationUserRequest) {
        return userRepository.findById(userId)
                .map(user -> {
                    user.setUsername(applicationUserRequest.getUsername());
                    user.setEmail(applicationUserRequest.getEmail());
                    return userRepository.save(user);
                }).orElseThrow(() -> new ResourceNotFoundException("ApplicationUser not found with id " + userId));
    }

    @DeleteMapping("/user/{userId}")
    //@CrossOrigin(origins = "http://localhost:3000")
    public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
        return userRepository.findById(userId)
                .map(user -> {
                    userRepository.delete(user);
                    return ResponseEntity.ok().build();
                }).orElseThrow(() -> new ResourceNotFoundException("ApplicationUser not found with id " + userId));
    }
}
