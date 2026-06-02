<?php
require_once 'auth/security.php';
require_once 'config/db.php';

// 1. Cargamos cabeceras y sesión (Punto 6)
setCabecerasSeguridad();
iniciarSesionSegura();

// 2. MIDDLEWARE DE AUTORIZACIÓN (Punto 5)
// Si no hay sesión iniciada, redirigimos al login
if (empty($_SESSION['user_id'])) {
    header("Location: auth/login.php");
    exit;
}

// Datos para la interfaz
$email_usuario = $_SESSION['user_id']; 
$rol_usuario = $_SESSION['user_rol'];
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Dashboard Seguro</title>
    <style>
        body { font-family: sans-serif; padding: 20px; line-height: 1.6; }
        .card { border: 1px solid #ccc; padding: 15px; border-radius: 8px; background: #f9f9f9; }
        .status { color: green; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Bienvenido al Sistema Seguro</h1>
    
    <div class="card">
        <h3>Información de la Sesión Actual:</h3>
        <p><strong>Estado:</strong> <span class="status">Autenticado con éxito</span></p>
        <p><strong>Identificador (Email):</strong> <?= htmlspecialchars($email_usuario) ?></p>
        <p><strong>Rol Asignado:</strong> <?= htmlspecialchars($rol_usuario) ?></p>
    </div>

   
    <br>
    <a href="auth/logout.php">Cerrar Sesión</a>
</body>
</html>