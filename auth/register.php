<?php
require_once '../config/db.php';
require_once 'security.php';

// Ejecutamos seguridad desde el segundo cero
setCabecerasSeguridad();
iniciarSesionSegura();

$mensaje = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // PUNTO 4: Validación del Token CSRF
    if (!validarCSRF($_POST['csrf_token'] ?? '')) {
        die('Fallo de seguridad: Token CSRF no válido o expirado.');
    }

    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';

    if ($email && !empty($password)) {
        // PUNTO 2: Registro con password_hash() dentro de la función
        if (registrarUsuario($pdo, $email, $password)) {
            $mensaje = "<p style='color:green'>Usuario creado. <a href='login.php'>Ir al Login</a></p>";
        } else {
            $mensaje = "<p style='color:red'>Error: El email ya existe o es inválido.</p>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head><title>Registro Seguro</title></head>
<body>
    <h2>Formulario de Registro</h2>
    <?= $mensaje ?>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?= getCSRFToken() ?>">
        
        <input type="email" name="email" placeholder="Email" required><br><br>
        <input type="password" name="password" placeholder="Contraseña" required><br><br>
        <button type="submit">Registrarse</button>
    </form>
</body>
</html>