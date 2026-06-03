<?php
require_once '../config/db.php';
require_once 'security.php';

// Ejecutamos seguridad desde el segundo cero
setCabecerasSeguridad();
iniciarSesionSegura();

$mensaje = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validarCSRF($_POST['csrf_token'] ?? '')) {
        die('Fallo de seguridad: Token CSRF no válido.');
    }

    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';

    // 1. Validar fortaleza de la contraseña
    $errores_password = validarFortalezaPassword($password);

    if (!empty($errores_password)) {
        // Si hay errores, los unimos en un mensaje con formato
        $mensaje = "<div style='color:red; background:#fee; padding:10px; border-radius:5px;'>";
        $mensaje .= "<strong>La contraseña no cumple los requisitos:</strong><br>";
        foreach ($errores_password as $error) {
            $mensaje .= "• " . htmlspecialchars($error) . "<br>";
        }
        $mensaje .= "</div>";
    } elseif ($email && !empty($password)) {
        // 2. Si pasa la validacion, procedemos al registro
        if (registrarUsuario($pdo, $email, $password)) {
            $mensaje = "<p style='color:green'>Usuario creado con éxito. <a href='login.php'>Ir al Login</a></p>";
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