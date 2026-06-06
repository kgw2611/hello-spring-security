package kr.ac.hansung.config;

import kr.ac.hansung.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    public SecurityConfig(CustomUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        // 누구나 접근 가능
                        .requestMatchers(
                                "/",
                                "/login",
                                "/signup",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/favicon.ico"
                        ).permitAll()

                        // 관리자 페이지
                        .requestMatchers("/admin/**").hasRole("ADMIN")

                        // 상품 등록/삭제/수정은 ADMIN만 가능
                        .requestMatchers(
                                "/products/add",
                                "/products/*/delete",
                                "/products/*/edit"
                        ).hasRole("ADMIN")

                        // 상품 등록 POST도 ADMIN만 가능
                        .requestMatchers(HttpMethod.POST, "/products").hasRole("ADMIN")

                        // 비밀번호 변경은 로그인 사용자만 가능
                        .requestMatchers("/user/password").authenticated()

                        // 나머지는 로그인 필요
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/home", true)
                        .failureUrl("/login?error")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .userDetailsService(userDetailsService);

        return http.build();
    }
}