<?php
require_once '../config/db.php';
require_once 'security.php';

setCabecerasSeguridad();
iniciarSesionSegura();

$mensaje = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validarCSRF($_POST['csrf_token'] ?? '')) {
        die('Fallo de seguridad: Token CSRF no válido.');
    }

    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';

    // USAMOS LA FUNCIÓN DEL PROFESOR: loginUsuario($pdo, $email, $password)
    // Esta función ya hace el SELECT, el password_verify y el session_regenerate_id internamente.
    if (loginUsuario($pdo, $email, $password)) {
        
        // La función del profesor ya guardó $_SESSION['user_id'] y $_SESSION['user_rol']
        // Así que solo redirigimos:
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