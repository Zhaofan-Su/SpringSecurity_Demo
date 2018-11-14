package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ParameterBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.Parameter;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableSwagger2
public class SwaggerConfig {

    // 设置默认TOKEN，方便测试
    private static final String TOKEN = "Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ6aGFveGluZ3VvLVtST0xFX0FETUlOLCBBVVRIX1dSSVRFXSIsImV4cCI6MTUzOTMzOTM0NX0.P9dkLQ7lpNODJppHBM-InSS90nw0XJieK8QNlZM0TeuNNQ8sUPYH-uif099A1-P2Ap6b_9lCLbXL2iR0OLdFyw";

    @Bean
    public Docket api() {

        ParameterBuilder ticketPar = new ParameterBuilder();
        List<Parameter> pars = new ArrayList<Parameter>();
        ticketPar.name("Authorization").description("校验")
                .modelRef(new ModelRef("string")).parameterType("header")
                .required(false).build();
        pars.add(ticketPar.build());

        return new Docket(DocumentationType.SWAGGER_2)
                .useDefaultResponseMessages(false)
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.example.demo"))
                .paths(PathSelectors.any())
                .build()
                .globalOperationParameters(pars);

    }


}

