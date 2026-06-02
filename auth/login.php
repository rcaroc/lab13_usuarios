<?php
require_once '../config/db.php';
require_once 'security.php';

setCabecerasSeguridad();
iniciarSesionSegura();

$mensaje = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // PUNTO 4: Validación CSRF (Obligatorio en todo POST)
    if (!validarCSRF($_POST['csrf_token'] ?? '')) {
        die('Fallo de seguridad: Token CSRF no válido.');
    }

    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';

    // Buscamos al usuario
    $stmt = $pdo->prepare("SELECT id, password, rol FROM usuarios WHERE email = ?");
    $stmt->execute([$email]);
    $usuario = $stmt->fetch();

    // PUNTO 3: Verificación del hash y regeneración de sesión
    if ($usuario && verificarPassword($password, $usuario['password'])) {
        
        // SEGURIDAD: Regeneramos el ID para evitar Session Fixation
        session_regenerate_id(true);
        
        // Guardamos datos en la sesión
        $_SESSION['user_id'] = $usuario['id'];
        $_SESSION['user_rol'] = $usuario['rol']; // Para el Punto 5
        $_SESSION['ultimo_acceso'] = time();

        // Redirigimos según el Punto 5 (Middleware de Roles)
        header("Location: ../dashboard.php");
        exit;
    } else {
        $mensaje = "<p style='color:red'>Credenciales inválidas.</p>";
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head><title>Login Seguro</title></head>
<body>
    <h2>Iniciar Sesión</h2>
    <?= $mensaje ?>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?= getCSRFToken() ?>">
        <input type="email" name="email" placeholder="Email" required><br><br>
        <input type="password" name="password" placeholder="Contraseña" required><br><br>
        <button type="submit">Entrar</button>
    </form>
</body>
</html>