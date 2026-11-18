# Build context is the backend/ directory so the parent pom is available.
#
#   docker build -f report/Dockerfile -t securebank-report backend

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build

COPY pom.xml ./
COPY core/pom.xml ./core/
COPY report/pom.xml ./report/
RUN mvn -q -B -pl report -am dependency:go-offline || true

COPY core ./core
COPY report ./report
RUN mvn -q -B -pl report -am package -DskipTests

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# curl is needed by the compose healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/report/target/*.jar app.jar
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
