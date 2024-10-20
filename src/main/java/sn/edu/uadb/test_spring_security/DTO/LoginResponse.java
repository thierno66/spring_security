package sn.edu.uadb.test_spring_security.DTO;


import java.util.List;

public class LoginResponse {
    private String username;
    private List<String> roles;
    private String token;

    public LoginResponse() {
    }

    public LoginResponse(String username, List<String> roles, String token) {
        this.username = username;
        this.roles = roles;
        this.token = token;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
