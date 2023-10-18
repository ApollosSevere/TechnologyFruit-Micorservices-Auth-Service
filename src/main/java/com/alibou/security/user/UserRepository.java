package com.alibou.security.user;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.alibou.security.token.Token;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

  Optional<User> findByEmail(String email);

}
