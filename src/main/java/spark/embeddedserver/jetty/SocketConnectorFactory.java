/*
 * Copyright 2015 - Per Wendel
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package spark.embeddedserver.jetty;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.ssl.SslStores;
import spark.utils.Assert;

import java.util.concurrent.TimeUnit;

/**
 * Creates socket connectors.
 */
public class SocketConnectorFactory {

    private static final Logger logger = LoggerFactory.getLogger(SocketConnectorFactory.class);

    /**
     * Creates an ordinary, non-secured Jetty server jetty.
     *
     * @param server Jetty server
     * @param host   host
     * @param port   port
     * @return - a server jetty
     */
    public static ServerConnector createSocketConnector(Server server, String host, int port) {
        Assert.notNull(server, "'server' must not be null");
        Assert.notNull(host, "'host' must not be null");

        ServerConnector connector = new ServerConnector(server);
        initializeConnector(connector, host, port);
        return connector;
    }

    /**
     * Creates a ssl jetty socket jetty. Keystore required, truststore
     * optional. If truststore not specified keystore will be reused.
     *
     * @param server    Jetty server
     * @param sslStores the security sslStores.
     * @param host      host
     * @param port      port
     * @return a ssl socket jetty
     */
    public static ServerConnector createSecureSocketConnector(Server server,
                                                              String host,
                                                              int port,
                                                              SslStores sslStores) {
        Assert.notNull(server, "'server' must not be null");
        Assert.notNull(host, "'host' must not be null");
        Assert.notNull(sslStores, "'sslStores' must not be null");

        SslContextFactory sslContextFactory = new SslContextFactory(sslStores.keystoreFile());

        if (sslStores.keystorePassword() != null) {
            sslContextFactory.setKeyStorePassword(sslStores.keystorePassword());
        }

        if (sslStores.trustStoreFile() != null) {
            sslContextFactory.setTrustStorePath(sslStores.trustStoreFile());
        }

        if (sslStores.trustStorePassword() != null) {
            sslContextFactory.setTrustStorePassword(sslStores.trustStorePassword());
        }


        moreSecure(sslContextFactory);
        ServerConnector connector = new ServerConnector(server, sslContextFactory);
        initializeConnector(connector, host, port);
        return connector;
    }

    private static void moreSecure(SslContextFactory sslContextFactory) {
        String property = System.getProperty("web.server.local");
        logger.info("System property web.server.local="+property);
        if (property != null && property.equals("true")){
            logger.info("Standard security");
            return;
        }

        String[] includeCiphers = {
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        };
        String[] excludeCiphers = {
                ".*RC4.*",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                ".*3DES.*",
                "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "SSL_RSA_WITH_DES_CBC_SHA",
                "SSL_DHE_RSA_WITH_DES_CBC_SHA",
                "SSL_DHE_DSS_WITH_DES_CBC_SHA",
                "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
                "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
                // Disable cipher suites with Diffie-Hellman key exchange to prevent Logjam attack
                //and avoid the ssl_error_weak_server_ephemeral_dh_key error in recent browsers
                //http://stackoverflow.com/questions/30523324/how-to-config-local-jetty-ssl-to-avoid-weak-phermeral-dh-key-error
                "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
                "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                "TLS_DHE.*", "TLS_EDH.*"

        };
        sslContextFactory.setIncludeCipherSuites(includeCiphers);

        sslContextFactory.setExcludeCipherSuites(excludeCiphers);

        sslContextFactory.setRenegotiationAllowed(false);

        sslContextFactory.addExcludeProtocols("SSLv3");
        sslContextFactory.addExcludeProtocols("TLSv1");
        sslContextFactory.addExcludeProtocols("TLSv1.1");

        logger.info("v4");
        logger.info("High security");
    }

    private static void initializeConnector(ServerConnector connector, String host, int port) {
        // Set some timeout options to make debugging easier.
        connector.setIdleTimeout(TimeUnit.HOURS.toMillis(1));
        connector.setSoLingerTime(-1);
        connector.setHost(host);
        connector.setPort(port);
    }

}


