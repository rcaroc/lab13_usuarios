<?php
// auth/security.php – Funciones de seguridad centralizadas
 
// ─── 1. CABECERAS DE SEGURIDAD HTTP ──────────────────────────────────────────
function setCabecerasSeguridad(): void {
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'");
}
 
// ─── 2. GESTIÓN SEGURA DE SESIONES ───────────────────────────────────────────
function iniciarSesionSegura(): void {
    ini_set('session.cookie_httponly',  1);
    ini_set('session.cookie_secure',    1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();
}
 
// ─── 3. REGISTRO CON BCRYPT ──────────────────────────────────────────────────
function registrarUsuario(PDO $pdo, string $email, string $password): bool {
    // Validar email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return false;
    // Hash seguro con bcrypt (cost 12)
    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $pdo->prepare(
        "INSERT INTO usuarios (email, password_hash, rol) VALUES (:e, :h, 'usuario')"
    );
    $stmt->execute([':e' => $email, ':h' => $hash]);
    return true;
}
 
// ─── 4. LOGIN CON VERIFICACIÓN SEGURA ────────────────────────────────────────
function loginUsuario(PDO $pdo, string $email, string $password): bool {
    $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE email = :email");
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch();
    if (!$user || !password_verify($password, $user['password_hash'])) return false;
    session_regenerate_id(true);    // Previene session fixation
    $_SESSION['user_id']  = $user['id'];
    $_SESSION['user_rol'] = $user['rol'];
    $_SESSION['user_ip']  = $_SERVER['REMOTE_ADDR'];
    return true;
}
 
// ─── 5. TOKEN CSRF ───────────────────────────────────────────────────────────
function getCSRFToken(): string {
    if (empty($_SESSION['csrf_token']))
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf_token'];
}
function validarCSRF(string $token): bool {
    return hash_equals($_SESSION['csrf_token'] ?? '', $token);
}
 
// ─── 6. CONTROL DE ACCESO POR ROL ────────────────────────────────────────────
function requireRol(string $rol): void {
    if (empty($_SESSION['user_id'])) {
        header('Location: /auth/login.php'); exit;
    }
    if ($_SESSION['user_rol'] !== $rol) {
        http_response_code(403);
        die('<h2>403 – Acceso denegado: se requiere rol ' . htmlspecialchars($rol) . '</h2>');
    }
}
 
