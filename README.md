## Cómo ejecutar el programa 

#Servidor:
1. Ubicarse en la carpeta src.
- Comando recomendado: cd src
2. Compilar el programa, específicamente los archivos: Servidor.java, Cliente.java, ThreadServidor.java, ThreadCliente.java
- Comando recomendado: javac Servidor.java Cliente.java ThreadServidor.java ThreadCliente.java
3. Ejecutar el servidor
- Comando recomendado: java Servidor
4. Aparecerán 2 opciones: con la opción 1 se genera el par de llaves y con la opción 2 se inicializa el servidor para manejar las peticiones del cliente. Se debe ejecutar la opción 1 y después la 2
5. Abrir una nueva terminal y seguir las siguientes instrucciones para inicializar los procesos del cliente

#Cliente:
1. Ubicarse en la carpeta src.
- Comando recomendado: cd src
2. Ejecutar el cliente
- Comando recomendado: java Cliente
3. Escoger una opción con el número indicado por consola
4. Visualizar la salida por consola tanto del cliente como del servidor que se está actualizando con respecto a las peticiones del cliente

Notas:
1. El cliente nunca se finaliza para facilitar las pruebas. De esta manera, al hacer enter después de terminar un proceso en la terminal de cliente se vuelve a ofrecer el menú
2. Si se siguen los mensajes de consola se pueden ver los pasos descritos por el enunciado simulados. Los tiempos de ejecución son lo último que se imprime por control. Para seguir cuando termina y empieza una petición este es un punto de referencia
3. Al no ser obligatorio, no se hizo uso de openssl para generar P y G