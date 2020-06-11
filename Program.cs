using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace CertHelper
{
    internal static class Program
    {
        #region Methods

        // Очистка CRLs
        private static void CleanCRLs()
        {
            string keyName = @"Software\Microsoft\SystemCertificates\CA";

            // Очищаем старые CRL в пользовательской ветке
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(keyName, true))
            {
                try { key.DeleteSubKeyTree("CRLs"); }
                catch (Exception e) { Console.WriteLine(e.Message); }
            }

            // Очищаем старые CRL в ветке локального компьютера
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyName, true))
            {
                try { key.DeleteSubKeyTree("CRLs"); }
                catch (Exception e) { Console.WriteLine(e.Message); }
            }
        }

        /// <summary>
        /// Главная точка входа для приложения.
        /// </summary>
        [STAThread]
        private static void Main()
        {
            CleanCRLs();
            RemoveCerts(StoreName.My);
            RemoveCerts(StoreName.Root);
            RemoveCerts(StoreName.CertificateAuthority);
            RemoveCerts(StoreName.AuthRoot);
            RemoveCerts(StoreName.TrustedPublisher);
            RemoveCerts(StoreName.TrustedPeople);
            RemoveCerts(StoreName.AddressBook);
        }

        private static void RemoveCerts(StoreName local_store)
        {
            try
            {
                string[] files = Directory.GetFiles("certs");

                X509Store store = new X509Store(local_store, StoreLocation.CurrentUser);
                store.Open(OpenFlags.MaxAllowed);

                foreach (string cert in files)
                {
                    // Берём серийные номера сертификатов из нашей папки с сертификатами
                    X509Certificate2 certificate = new X509Certificate2(cert);
                    string serialHex = certificate.SerialNumber;

                    // Находим данный сертификат в хранилище и удаляем его
                    X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindBySerialNumber, serialHex, false);
                    foreach (var cur_cert in col)
                    {
                        // Если где-то ошибка, то пропускаем такой серт
                        try { store.Remove(cur_cert); }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                            continue;
                        }
                    }
                }
                store.Close();
                Console.WriteLine(local_store + " store is cleaned.");
            }
            catch { }
        }

        #endregion Methods
    }
}