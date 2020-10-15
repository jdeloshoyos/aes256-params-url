using System;

namespace ejemplo_cifrado_aes256
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Ejemplo de cifrado y encoding de parámetros");
            Console.WriteLine("(c) 2020 Jaime de los Hoyos M.");
            Console.WriteLine("-------------------------------------------\n");

            // Declaramos los inputs que usaremos
            string payload = "{\"username\": \"nom_usuario\",\"orderPlacerNum\": \"AV1234567890\",\"patientexternalid\": \"1234567\"}";
            string secreto = "ClaveSuperSecreta!!";

            Console.WriteLine("Payload: " + payload);
            Console.WriteLine("Secreto: " + secreto);

            Console.WriteLine("\nPASO 1. CIFRADO DEL PAYLOAD\n");

            string payload_cifrado = MetodosCifrado.EncriptaParametros(payload, secreto);
            Console.WriteLine("Payload cifrado: " + payload_cifrado);
            Console.WriteLine("Ejemplo de URL: http://miservidor.com/ruta/metodo?params=" + payload_cifrado);
            Console.WriteLine("\nPASO 2. DESCIFRADO DEL PAYLOAD\n");

            string payload_descifrado = MetodosCifrado.DecriptaParametros(payload_cifrado, secreto);
            Console.WriteLine("Payload descifrado: " + payload_descifrado);

        }
    }
}
