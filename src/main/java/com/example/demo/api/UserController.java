package com.example.demo.api;

import com.example.demo.constant.ConstantKey;
import com.example.demo.exception.UsernameIsExitedException;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.util.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected BCryptPasswordEncoder bCryptPasswordEncoder;

    @RequestMapping(value = "/signup", method = RequestMethod.POST)
    public User signup(@RequestBody User user) {
        User bizUser = userRepository.findByUsername(user.getUsername());
        if(null != bizUser){
            throw new UsernameIsExitedException("用户已经存在");
        }
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public void login(String username, String password, HttpServletResponse response) {
        User userVo = userRepository.findByUsername(username);
        if (userVo != null) {
            List roleList = new ArrayList<>();
            String subject = userVo.getUsername() + "-" + roleList;
            String token = Jwts.builder()
                    .setSubject(subject)
                    // 设置过期时间 365 * 24 * 60 * 60秒(1年)
                    .setExpiration(new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000))
                    //加密算法采用HS512
                    .signWith(SignatureAlgorithm.HS512, "MyJwtSecret")
                    .compact();
            // 登录成功后，返回token到header里面
            response.addHeader("Authorization", "Bearer " + token);

        }

    }

    @RequestMapping(value = "/userList", method = RequestMethod.GET)
    public Map<String, Object> userList(){
        List<User> users = userRepository.findAll();
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("users",users);
        return map;
    }

    @RequestMapping(value = "/authorityList", method = RequestMethod.GET)
    public List<String> authorityList(){
        List<String> authentication = getAuthentication();
        return authentication;
    }

    @RequestMapping(value = "/hello", method = RequestMethod.GET)
    public String hello(){

        return "hello";
    }
    public List<String> getAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        List<String> list = new ArrayList<>();
        for (GrantedAuthority grantedAuthority : authorities) {
            list.add(grantedAuthority.getAuthority());
        }
        return list;
    }



}
