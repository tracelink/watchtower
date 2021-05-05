FROM maven:3.6.3-openjdk-8-slim AS build
COPY . /tmp/watchtower
WORKDIR /tmp/watchtower
RUN mvn clean package -DskipTests -T4

FROM adoptopenjdk/openjdk8:ubi
RUN dnf install python38 -y
RUN python3 -m ensurepip --upgrade
RUN dnf module install nodejs:12 -y
COPY --from=build /tmp/watchtower/watchtower-web/target/watchtower*SNAPSHOT.jar /opt/watchtower/watchtower.jar
RUN useradd watchtoweruser
RUN chown -R watchtoweruser /opt/watchtower/
USER watchtoweruser
WORKDIR /opt/watchtower/
ENV VIRTUAL_ENV=/opt/watchtower/pythonvenv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENTRYPOINT ["java", "-jar", "/opt/watchtower/watchtower.jar"]

