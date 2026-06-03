<?php
require_once 'auth/security.php';
require_once 'config/db.php';

// 1. Cargamos cabeceras y sesión 
setCabecerasSeguridad();
iniciarSesionSegura();

//  MIDDLEWARE DE AUTORIZACIÓN 
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
    <?php if ($_SESSION['user_rol'] === 'admin'): ?>
        <div style="margin-top: 20px; padding: 15px; background: #e9ecef; border-left: 5px solid #007bff;">
            <h4>Acceso Administrativo Detectado</h4>
            <p>Tienes permisos para gestionar la plataforma.</p>
            <a href="admin/index.php" style="display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px;">
                Ir al Panel de Administración
            </a>
        </div>
    <?php endif; ?>


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