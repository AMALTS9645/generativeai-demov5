 import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;

@SpringBootApplication
public class LoginApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginApiApplication.class, args);
    }
}

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Controller for handling login requests.
 */
@RestController
@RequestMapping("/api/login")
public class LoginController {

    @Autowired
    private AuthenticationService authenticationService;

    /**
     * Endpoint for user login.
     *
     * @param requestBody The request body containing the login credentials.
     * @return ResponseEntity with user information or an error message.
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, Object> requestBody) {
        try {
            String username = (String) requestBody.get("username");
            String password = (String) requestBody.get("password");

            if (!username.matches("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")) {
                throw new IllegalArgumentException("Invalid email format");
            }

            User user = authenticationService.authenticateUser(username, password);

            if (user != null) {
                return ResponseEntity.ok().body(userToMap(user));
            } else {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid username or password"));
            }
        } catch (Exception e) {
            // Log the exception for debugging purposes
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    private Map<String, Object> userToMap(User user) {
        Map<String, Object> userMap = new HashMap<>();
        userMap.put("id", user.getId());
        userMap.put("username", user.getUsername());
        userMap.put("email", user.getEmail());
        return userMap;
    }
}

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for handling user authentication.
 */
@Service
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final Set<User> users;

    @Autowired
    public AuthenticationService(PasswordEncoder passwordEncoder, Set<User> users) {
        this.passwordEncoder = passwordEncoder;
        this.users = users;
    }

    /**
     * Authenticates a user with the provided credentials.
     *
     * @param username The username of the user.
     * @param password The password of the user.
     * @return The authenticated user if successful, otherwise null.
     */
    public User authenticateUser(String username, String password) {
        User user = users.stream()
                .filter(u -> u.getUsername().equals(username) && passwordEncoder.matches(password, u.getPassword()))
                .findFirst()
                .orElse(null);

        return user;
    }
}

import org.springframework.security.crypto.password.PasswordEncoder;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * User entity.
 */
public class User {

    private final int id;
    private final String username;
    private final String email;
    private final String password;

    public User(int id, String username, String email, String password) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
    }

    public int getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return id == user.id &&
                Objects.equals(username, user.username) &&
                Objects.equals(email, user.email) &&
                Objects.equals(password, user.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, username, email, password);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                '}';
    }

    public static List<User> createSampleUsers() {
        List<User> sampleUsers = new ArrayList<>();
        sampleUsers.add(new User(1, "user1", "user1@example.com", "password1"));
        sampleUsers.add(new User(2, "user2", "user2@example.com", "password2"));
        sampleUsers.add(new User(3, "user3", "user3@example.com", "password3"));
        return sampleUsers;
    }
}

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.NoSuchAlgorithmException;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() throws NoSuchAlgorithmException {
        return new BCryptPasswordEncoder();
    }
}