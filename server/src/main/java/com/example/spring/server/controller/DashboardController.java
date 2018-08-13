package com.example.spring.server.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/dashboard")
public class DashboardController {

    @GetMapping("/")
    public Map<String, Object> loadDashboard(HttpServletRequest request, HttpServletResponse resp) {
        HashMap<String, Object> response = new HashMap<>();
        response.put("data", "User login successful");
        return response;
    }
}
