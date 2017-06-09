FROM 10.39.101.226:5000/frolvlad/alpine-oraclejdk8:slim
VOLUME /tmp
ADD cloud.security.service-1.0.jar app.jar
EXPOSE 3080
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]