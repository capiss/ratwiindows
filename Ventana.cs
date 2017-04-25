using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
//Cabecera Adicional para el uso de DllImport
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Threading;
using System.IO;



namespace pm3candc
{
    //Clase para la verificación de la ventana actual
    class Ventana
    {
        //Se importa de user32.dll una funcion que devuelve un puntero a la Ventana Activa actual
        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();


        //Se importa de user32.dll una funcion que escribe en un buffer el nombre de una ventana y devuelve la longitud de ese nombre
        //hWnd -> puntero de la ventana que se desea saber el nombre
        //text -> nombre devuelto
        //count -> numero de caracteres maximos que se leeran del nombre
        [DllImport("user32.dll")]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);


        //Funcion que devuelva el nombre de la ventana actual
        public string NombreDeVentana()
        {
            //Numero de catacteres a leer
            const int caracteres = 256;
            //Se crea un buffer donde leeremos el titulo de la ventana (de "caracteres" tamaño)
            StringBuilder Buffer = new StringBuilder(caracteres);
            //Se obtiene el puntero a la ventana actual
            IntPtr handle = GetForegroundWindow();
            //Si la longitud del nombre es mayor a 0
            if (GetWindowText(handle, Buffer, caracteres) > 0)
            {
                //Regresamos un String que contenga el nombre de la ventana
                return Buffer.ToString();
            }
            //Si no tiene longitud, para no regresar basura en el buffer, regresamos una cadena de longitud 0
            return "";
        }
    }
}

