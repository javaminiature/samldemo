package com.javaminiature.samldemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.javaminiature.samldemo.configuration.IDPConfiguration;


@SpringBootApplication
@EnableConfigurationProperties(IDPConfiguration.class)
public class App 
{
    public static void main( String[] args )
    {
    	SpringApplication.run(App.class, args);
    }
}

