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
function loginUsuario(PDO $pdo, string $email, string $password, string &$mensaje_error = ""): bool {
    // 1. Buscar al usuario
    $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE email = :email");
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch();

    if (!$user) {
        $mensaje_error = "Credenciales inválidas.";
        return false;
    }

    // 2. Verificar si la cuenta está bloqueada temporalmente
    if (!empty($user['bloqueado_hasta'])) {
        $ahora = new DateTime("now", new DateTimeZone("UTC"));
        $bloqueo = new DateTime($user['bloqueado_hasta'], new DateTimeZone("UTC"));

        if ($ahora < $bloqueo) {
            $intervalo = $bloqueo->diff($ahora);
            $minutos_restantes = $intervalo->i + 1; // Redondeo hacia arriba para el usuario
            $mensaje_error = "Cuenta bloqueada temporalmente. Intente de nuevo en " . $minutos_restantes . " minutos.";
            return false;
        } else {
            // El tiempo ya expiró: Limpiamos el bloqueo de forma automática en la BD
            $stmtReset = $pdo->prepare("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = :id");
            $stmtReset->execute([':id' => $user['id']]);
            $user['intentos_fallidos'] = 0; // Actualizamos la variable local
        }
    }

    // 3. Verificar la contraseña
    if (!password_verify($password, $user['password_hash'])) {
        $nuevos_intentos = $user['intentos_fallidos'] + 1;
        
        if ($nuevos_intentos >= 3) {
            // Calculamos los 15 minutos en el futuro
            $fecha_bloqueo = new DateTime("now", new DateTimeZone("UTC"));
            $fecha_bloqueo->modify('+15 minutes');
            $timestamp_bloqueo = $fecha_bloqueo->format('Y-m-d H:i:sO');

            $stmtLock = $pdo->prepare("UPDATE usuarios SET intentos_fallidos = :intentos, bloqueado_hasta = :bloqueo WHERE id = :id");
            $stmtLock->execute([
                ':intentos' => $nuevos_intentos,
                ':bloqueo' => $timestamp_bloqueo,
                ':id' => $user['id']
            ]);
            
            $mensaje_error = "Demasiados intentos fallidos. Su cuenta ha sido bloqueada por 15 minutos.";
        } else {
            // Sumar el intento fallido
            $stmtUpdate = $pdo->prepare("UPDATE usuarios SET intentos_fallidos = :intentos WHERE id = :id");
            $stmtUpdate->execute([
                ':intentos' => $nuevos_intentos,
                ':id' => $user['id']
            ]);
            
            $intentos_restantes = 3 - $nuevos_intentos;
            $mensaje_error = "Credenciales inválidas. Le quedan " . $intentos_restantes . " intentos.";
        }
        return false;
    }

    // 4. Autenticación Exitosa: Reiniciar parámetros de bloqueo y regenerar sesión
    $stmtSuccess = $pdo->prepare("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = :id");
    $stmtSuccess->execute([':id' => $user['id']]);

    session_regenerate_id(true); // Previene session fixation
    $_SESSION['user_id']  = $user['id']; // Conserva tu lógica con ID numérico o Email según tu Supabase
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
 
