<?php
class Database {
    private $conn;

    public function __construct($conn) {
        $this->conn = $conn; // mysqli connection
    }

    // Execute SELECT queries that return a single row
    public function fetchOne(string $query, array $params, string $types = ''): ?array {
        $stmt = $this->conn->prepare($query);
        if (!$stmt) throw new Exception("Prepare failed: " . $this->conn->error);

        if ($params) {
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        return $row ?: null;
    }

    // Execute SELECT queries that return multiple rows
    public function fetchAll(string $query, array $params = [], string $types = ''): array {
        $stmt = $this->conn->prepare($query);
        if (!$stmt) throw new Exception("Prepare failed: " . $this->conn->error);

        if ($params) {
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();
        $result = $stmt->get_result();
        $rows = $result->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
        return $rows;
    }

    // Execute INSERT, UPDATE, DELETE queries
    public function execute(string $query, array $params = [], string $types = ''): bool {
        $stmt = $this->conn->prepare($query);
        if (!$stmt) throw new Exception("Prepare failed: " . $this->conn->error);

        if ($params) {
            $stmt->bind_param($types, ...$params);
        }

        $success = $stmt->execute();
        $stmt->close();
        return $success;
    }

    // Utility for COUNT(*) checks
    public function count(string $query, array $params = [], string $types = ''): int {
        $stmt = $this->conn->prepare($query);
        if (!$stmt) throw new Exception("Prepare failed: " . $this->conn->error);

        if ($params) {
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();
        $stmt->bind_result($count);
        $stmt->fetch();
        $stmt->close();
        return $count;
    }
}
?>
