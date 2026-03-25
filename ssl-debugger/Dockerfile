FROM eclipse-temurin:25-jre
WORKDIR /app
COPY build/libs/ssl-debugger.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
