# Packages the application into a runnable Docker container

FROM openjdk:8-jdk-alpine

COPY target/e2e-tests.jar /
COPY target/pom.xml /
COPY target/mvnw /
COPY target/.mvn /.mvn

ENTRYPOINT ["./mvnw", "test"]
