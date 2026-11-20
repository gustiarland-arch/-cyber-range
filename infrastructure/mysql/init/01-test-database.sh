#!/bin/sh
# Creates the integration-test database and grants the app user access to it (dev only).
mysql -uroot -p"$MYSQL_ROOT_PASSWORD" <<SQL
CREATE DATABASE IF NOT EXISTS cyber_range_test CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
GRANT ALL PRIVILEGES ON cyber_range_test.* TO '${MYSQL_USER}'@'%';
FLUSH PRIVILEGES;
SQL
