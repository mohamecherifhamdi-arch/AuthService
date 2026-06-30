package com.school.auth.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class KafkaTopicConfig {

    @Bean
    public NewTopic authRequestsTopic() {
        return TopicBuilder.name("auth-requests")
                .partitions(1)
                .replicas(1)
                .build();
    }

    @Bean
    public NewTopic authResponsesTopic() {
        return TopicBuilder.name("auth-responses")
                .partitions(1)
                .replicas(1)
                .build();
    }
}
