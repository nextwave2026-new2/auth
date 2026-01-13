# Multi-stage build for Spring Boot application
# Stage 1: Get common library from Docker Hub
FROM lpham2026/nextwave-common:latest AS common

# Stage 2: Build application
FROM maven:3.9.6-eclipse-temurin-21-alpine AS build

WORKDIR /app

# Create Maven repository directory
RUN mkdir -p /root/.m2/repository/com/nextwave/common/1.0.0

# Copy common JAR from the common stage (file is named app.jar in the image)
COPY --from=common /app/app.jar /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.jar

# Create POM file for common library
RUN echo '<?xml version="1.0" encoding="UTF-8"?>' > /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.pom && \
    echo '<project xmlns="http://maven.apache.org/POM/4.0.0"' >> /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.pom && \
    echo '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' >> /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.pom && \
    echo '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' >> /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.pom && \
    echo '    <modelVersion>4.0.0</modelVersion>' >> /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.pom && \
    echo '    <groupId>com.nextwave</groupId>' >> /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.pom && \
    echo '    <artifactId>common</artifactId>' >> /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.pom && \
    echo '    <version>1.0.0</version>' >> /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.pom && \
    echo '</project>' >> /root/.m2/repository/com/nextwave/common/1.0.0/common-1.0.0.pom

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre-alpine

# Add non-root user for security
RUN addgroup -S spring && adduser -S spring -G spring

WORKDIR /app

# Copy jar from build stage
COPY --from=build /app/target/*.jar app.jar

# Change ownership
RUN chown -R spring:spring /app

# Switch to non-root user
USER spring:spring

# Expose port
EXPOSE 1000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:1000/actuator/health || exit 1

# Run application
ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-XX:+UseG1GC", \
    "-XX:+OptimizeStringConcat", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", \
    "app.jar"]
