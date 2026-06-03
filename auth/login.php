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
    
    // Variable auxiliar para capturar la razon del fallo
    $error_detallado = "";

    // Enviamos el parámetro adicional de error
    if (loginUsuario($pdo, $email, $password, $error_detallado)) {
        header("Location: ../dashboard.php");
        exit;
    } else {
        // Mostramos dinámicamente el mensaje provisto por security.php
        $mensaje = "<p style='color:red'>" . htmlspecialchars($error_detallado) . "</p>";
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