package hyunul.boilerplate.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig
        implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // 추가해줘야 static 경로 활용 가능.
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/");
    }
}
