using System;
using System.Net.Sockets;
using System.Net.Security;
using System.Threading.Tasks;
using System.Security.Authentication;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace TLS12TLS13NegotiateIssue
{
    class Program
    {
        static async Task Main(string[] args)
        {

            Console.WriteLine( typeof(SslStream).Assembly.Location);

            // This connection works.
            await ServerAsyncSslHelper(clientSslProtocols: null, SslProtocols.Tls13);
            // This connection works, but it causing the next conneetion fails. 
            await ServerAsyncSslHelper(clientSslProtocols: null, SslProtocols.Tls12);
            // Fails altought it works ontry #1 and it is caused by Tls12 connection above.
            await ServerAsyncSslHelper(clientSslProtocols: null, SslProtocols.Tls13);
        }

        private static (Socket clientSocket, Socket serverSocket) GetConnectedTcpStreams()
        {
            using (Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                listener.Bind(new IPEndPoint(IPAddress.Loopback, 5666));
                listener.Listen(1);

                var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                clientSocket.Connect(listener.LocalEndPoint);
                Socket serverSocket = listener.Accept();

                serverSocket.NoDelay = true;
                clientSocket.NoDelay = true;

                return (clientSocket, serverSocket);
            }

        }

        static private X509Certificate2 CreateCert()
        {
            // Create self-signed cert for server.
            using (RSA rsa = RSA.Create())
            {
                var certReq = new CertificateRequest("CN=contoso.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                certReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
                certReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
                X509Certificate2 cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMonths(-1), DateTimeOffset.UtcNow.AddMonths(1));
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return new X509Certificate2(cert.Export(X509ContentType.Pfx));
                }
                return cert;
            }
        }

        private static Task AuthenticateClientAsync(SslStream stream, string targetHost, bool checkCertificateRevocation, SslProtocols? protocols) =>
            protocols.HasValue ?
            stream.AuthenticateAsClientAsync(targetHost, null, protocols.Value, checkCertificateRevocation) :
            stream.AuthenticateAsClientAsync(targetHost, null, checkCertificateRevocation);

        private static Task AuthenticateServerAsync(SslStream stream, X509Certificate serverCertificate, bool clientCertificateRequired, bool checkCertificateRevocation, SslProtocols? protocols) =>
            protocols.HasValue ?
            stream.AuthenticateAsServerAsync(serverCertificate, clientCertificateRequired, protocols.Value, checkCertificateRevocation) :
            stream.AuthenticateAsServerAsync(serverCertificate, clientCertificateRequired, checkCertificateRevocation);

        private static async Task ServerAsyncSslHelper(
            SslProtocols? clientSslProtocols,
            SslProtocols serverSslProtocols)
        {
            Console.WriteLine("=======================================");
            Console.WriteLine(
                "Server: " + serverSslProtocols + "; Client: " + clientSslProtocols);

            (Socket clientSocket, Socket serverSocket) = GetConnectedTcpStreams();
            var clientStream = new NetworkStream(clientSocket, ownsSocket: true);
            var serverStream = new NetworkStream(serverSocket, ownsSocket: true);

            using (SslStream sslServerStream = new SslStream(
                serverStream,
                false,
                (_,__,___,____)=>true))
            using (SslStream sslClientStream = new SslStream(
                clientStream,
                false,
                (_, __, ___, ____) => true))
            {

                Console.WriteLine("Connected on {0} {1} ({2} {3})", clientSocket.LocalEndPoint, clientSocket.RemoteEndPoint, clientSocket.Handle, serverSocket.Handle);
                Console.WriteLine("client SslStream#{0} server SslStream#{1}", sslClientStream.GetHashCode(), sslServerStream.GetHashCode());
                using (X509Certificate2 serverCertificate = CreateCert())
                {
                    string serverName = serverCertificate.GetNameInfo(X509NameType.SimpleName, false);

                    try
                    {
                        await Task.WhenAll(
                            AuthenticateClientAsync(sslClientStream, serverName, false, clientSslProtocols),
                            AuthenticateServerAsync(sslServerStream, serverCertificate, false, false, serverSslProtocols)
                        );

                        Console.WriteLine(
                                "Server({0}) authenticated with encryption cipher: {1} {2}-bit strength",
                                serverSocket.LocalEndPoint,
                                sslServerStream.CipherAlgorithm,
                                sslServerStream.CipherStrength);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Exception : " + ex);
                        return;
                    }
                }

            }
        }
    }
}
