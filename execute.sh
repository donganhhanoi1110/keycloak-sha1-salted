echo "Change to Java 11"
export JAVA_HOME=$(/usr/libexec/java_home -v1.11)

mvn clean install -DskipTests
echo "Copy jar "
cp ./target/keycloak-sha1.jar /Users/nguyenminhanh/git-repos/aleph/genvita-middleware/microservices/gateway/src/main/docker/realm-config/keycloak-sha1.jar

echo "Run docker"
docker-compose -f /Users/nguyenminhanh/git-repos/aleph/genvita-middleware/microservices/gateway/src/main/docker/keycloak.yml up -d
