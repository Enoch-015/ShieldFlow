FROM apache/flink:1.18.1-scala_2.12

# Install Kafka SQL connector into classpath so it is always available
RUN mkdir -p /opt/flink/usrlib && \
    wget -q -P /opt/flink/lib \
      https://repo1.maven.org/maven2/org/apache/flink/flink-sql-connector-kafka/3.0.2-1.18/flink-sql-connector-kafka-3.0.2-1.18.jar
