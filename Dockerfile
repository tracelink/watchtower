FROM adoptopenjdk/openjdk8:ubi AS base
RUN dnf install python38 -y
RUN python3 -m ensurepip --upgrade
RUN pip3 install --upgrade pip
RUN dnf module install nodejs:12 -y
ENV VIRTUAL_ENV=/opt/watchtower/pythonvenv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

FROM base AS build
RUN dnf install maven -y
COPY . /tmp/watchtower
WORKDIR /tmp/watchtower
RUN mvn clean package -q -DskipTests

FROM base
COPY --from=build /tmp/watchtower/watchtower-web/target/watchtower*SNAPSHOT.jar /opt/watchtower/watchtower.jar
RUN useradd watchtoweruser
RUN chown -R watchtoweruser /opt/watchtower/
USER watchtoweruser
WORKDIR /opt/watchtower/
RUN pip3 install checkov==2.0.257 --no-cache-dir
RUN npm --prefix ./eslint_work install eslint@7.24.0
RUN npm --prefix ./eslint_work install estraverse@5.2.0
ENTRYPOINT ["java", "-jar", "/opt/watchtower/watchtower.jar"]

