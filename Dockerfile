# Usamos la imagen oficial de PHP con Apache
FROM php:8.2-apache

# Instalamos las extensiones necesarias para PostgreSQL (Supabase)
RUN apt-get update && apt-get install -y libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

# Habilitamos el módulo de reescritura de Apache (útil para rutas amigables)
RUN a2enmod rewrite

# Copiamos los archivos de nuestro proyecto al directorio del servidor
COPY . /var/www/html/

# Exponemos el puerto 80
EXPOSE 80