package com.apollostore.security;

import com.apollostore.security.auth.AuthenticationService;
import com.apollostore.security.payload.request.RegisterRequest;
import com.apollostore.security.user.Role;

import io.awspring.cloud.jdbc.config.annotation.RdsInstanceConfigurer;
import io.awspring.cloud.jdbc.datasource.TomcatJdbcDataSourceFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing(auditorAwareRef = "auditorAware")
public class AuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

//	@Bean
//	public RdsInstanceConfigurer instanceConfigurer() {
//		return ()-> {
//			TomcatJdbcDataSourceFactory dataSourceFactory =
//					new TomcatJdbcDataSourceFactory();
//			dataSourceFactory.setInitialSize(10);
//			dataSourceFactory.setValidationQuery("SELECT 1 FROM DUAL");
//			return dataSourceFactory;
//		};
//	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService service) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("admin@mail.com")
					.password("password")
					.role(Role.ADMIN)
					.build();
			System.out.println("Admin token: " + service.register(admin).getAccessToken());

			var manager = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("manager@mail.com")
					.password("password")
					.role(Role.MANAGER)
					.build();
			System.out.println("Manager token: " + service.register(manager).getAccessToken());

		};
	}
}
