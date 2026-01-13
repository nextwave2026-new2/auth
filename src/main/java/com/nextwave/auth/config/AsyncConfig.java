package com.nextwave.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Async Configuration
 * 
 * Enables asynchronous method execution for:
 * - Email sending
 * - Background tasks
 * - Non-blocking operations
 * 
 * @author NextWave Team
 * @version 1.0
 */
@Configuration
@EnableAsync
public class AsyncConfig {
}
