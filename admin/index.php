<?php
require_once '../auth/security.php';
require_once '../config/db.php';

setCabecerasSeguridad();
iniciarSesionSegura();

// Bloqueo de seguridad: Solo admins pueden entrar aquí
requireRol('admin');

$mensaje = "";

// Lógica para cambiar el rol si se recibe el formulario
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['usuario_id'], $_POST['nuevo_rol'])) {
    if (!validarCSRF($_POST['csrf_token'] ?? '')) {
        die('Token CSRF no válido.');
    }

    $u_id = (int)$_POST['usuario_id'];
    $nuevo_rol = $_POST['nuevo_rol'];

    $stmt = $pdo->prepare("UPDATE usuarios SET rol = :rol WHERE id = :id");
    if ($stmt->execute([':rol' => $nuevo_rol, ':id' => $u_id])) {
        $mensaje = "<p style='color:green'>Rol actualizado correctamente.</p>";
    }
}

// Consultar todos los usuarios
$usuarios = $pdo->query("SELECT id, email, rol, creado_en FROM usuarios ORDER BY id ASC")->fetchAll();
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Panel de Administración</title>
    <style>
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #f4f4f4; }
        .btn-update { background: #007bff; color: white; border: none; padding: 5px 10px; cursor: pointer; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Gestión de Usuarios (Admin)</h1>
    <p><a href="../dashboard.php">← Volver al Dashboard</a></p>
    <?= $mensaje ?>

    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Email</th>
                <th>Rol Actual</th>
                <th>Fecha Registro</th>
                <th>Acción</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($usuarios as $u): ?>
            <tr>
                <td><?= $u['id'] ?></td>
                <td><?= htmlspecialchars($u['email']) ?></td>
                <td><strong><?= htmlspecialchars($u['rol']) ?></strong></td>
                <td><?= $u['creado_en'] ?></td>
                <td>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="csrf_token" value="<?= getCSRFToken() ?>">
                        <input type="hidden" name="usuario_id" value="<?= $u['id'] ?>">
                        <select name="nuevo_rol">
                            <option value="usuario" <?= $u['rol'] === 'usuario' ? 'selected' : '' ?>>Usuario</option>
                            <option value="admin" <?= $u['rol'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                        </select>
                        <button type="submit" class="btn-update">Cambiar</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</body>
</html>