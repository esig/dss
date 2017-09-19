package eu.europa.esig.dss.client.http.commons;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.Protocol;
import eu.europa.esig.dss.client.http.commons.handler.NativeHTTPConnectionHandler;
import eu.europa.esig.dss.client.http.commons.handler.NativeHTTPRequestHandler;
import eu.europa.esig.dss.client.http.commons.handler.NativeHTTPResponseHandler;
import eu.europa.esig.dss.client.http.proxy.ProxyConfig;
import eu.europa.esig.dss.client.http.proxy.ProxyProperties;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.net.www.protocol.http.AuthCacheImpl;
import sun.net.www.protocol.http.AuthCacheValue;

import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

public class NativeCommonsDataLoader implements DataLoader {

    private static final Logger LOG = LoggerFactory.getLogger(NativeCommonsDataLoader.class);

    public static final int TIMEOUT_CONNECTION = 6000;

    public static final int TIMEOUT_SOCKET = 6000;

    public static final int CONNECTIONS_MAX_TOTAL = 20;

    public static final int CONNECTIONS_MAX_PER_ROUTE = 2;

    public static final String CONTENT_TYPE = "Content-Type";

    private static final String REQUEST_METHOD_POST = "POST";

    /**
     * information: <a href="http://www.oracle.com/technetwork/java/javase/8u111-relnotes-3124969.html">http://www.oracle.com/technetwork/java/javase/8u111-relnotes-3124969.html</a>
     */
    private static final String JDK_SYSTEM_PROPERTY_HTTPS_PROXY_AUTHENCATION_SCHEMAS = "jdk.http.auth.tunneling.disabledSchemes";

    protected String contentType;

    private ProxyConfig proxyConfig;

    private int timeoutConnection = TIMEOUT_CONNECTION;
    private int timeoutSocket = TIMEOUT_SOCKET;
    private int connectionsMaxTotal = CONNECTIONS_MAX_TOTAL;
    private int connectionsMaxPerRoute = CONNECTIONS_MAX_PER_ROUTE;

    private final Map<HttpHost, UsernamePasswordCredentials> authenticationMap = new HashMap<HttpHost, UsernamePasswordCredentials>();

    private boolean updated;

    private NativeHTTPConnectionHandler connectionHandler = null;
    private NativeHTTPRequestHandler requestHandler = null;
    private NativeHTTPResponseHandler responseHandler = null;

    private String defaultJdkHttpAuthProxyingDisabledSchemes;
    private boolean usePostRequestMethodForPost = false;

    private String sslKeystorePath;
    private String sslKeystoreType;
    private String sslKeystorePassword;
    private String sslTruststorePath;
    private String sslTruststoreType;
    private String sslTruststorePassword;
    private boolean sslTruststoreTrustEverything = false;

    /**
     * The default constructor for CommonsDataLoader.
     */
    public NativeCommonsDataLoader() {
        this(null);
    }

    /**
     * The constructor for CommonsDataLoader with defined content-type.
     *
     * @param contentType The content type of each request
     */
    public NativeCommonsDataLoader(final String contentType) {
        this.contentType = contentType;
        defaultJdkHttpAuthProxyingDisabledSchemes = System.getProperty(JDK_SYSTEM_PROPERTY_HTTPS_PROXY_AUTHENCATION_SCHEMAS);
    }

    private HttpClientConnectionManager getConnectionManager() throws DSSException {

        LOG.debug("HTTPS TrustStore undefined, using default");
        RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder = RegistryBuilder.create();
        socketFactoryRegistryBuilder = setConnectionManagerSchemeHttp(socketFactoryRegistryBuilder);
        socketFactoryRegistryBuilder = setConnectionManagerSchemeHttps(socketFactoryRegistryBuilder);

        final PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistryBuilder.build());

        connectionManager.setMaxTotal(getConnectionsMaxTotal());
        connectionManager.setDefaultMaxPerRoute(getConnectionsMaxPerRoute());

        LOG.debug("PoolingHttpClientConnectionManager: max total: " + connectionManager.getMaxTotal());
        LOG.debug("PoolingHttpClientConnectionManager: max per route: " + connectionManager.getDefaultMaxPerRoute());

        return connectionManager;
    }

    private RegistryBuilder<ConnectionSocketFactory> setConnectionManagerSchemeHttp(RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder) {
        return socketFactoryRegistryBuilder.register("http", PlainConnectionSocketFactory.getSocketFactory());
    }

    private RegistryBuilder<ConnectionSocketFactory> setConnectionManagerSchemeHttps(RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder) throws DSSException {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");

            TrustManager[] trustManagers = createTrustManagers();

            sslContext.init(createKeyManagers(), trustManagers, new SecureRandom());
            SSLContext.setDefault(sslContext);

            final SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContext);
            return socketFactoryRegistryBuilder.register("https", sslConnectionSocketFactory);
        } catch (Exception e) {
            throw new DSSException(e);
        }
    }

    @Override
    public byte[] get(final String urlString) {

        if (Protocol.isFileUrl(urlString)) {
            return fileGet(urlString);
        } else if (Protocol.isHttpUrl(urlString)) {
            return httpGet(urlString);
        } else if (Protocol.isFtpUrl(urlString)) {
            return ftpGet(urlString);
        } else if (Protocol.isLdapUrl(urlString)) {
            return ldapGet(urlString);
        } else {
            LOG.warn("DSS framework only supports HTTP, HTTPS, FTP and LDAP CRL's urlString.");
        }
        return httpGet(urlString);
    }

    @Override
    public DataAndUrl get(final List<String> urlStrings) {

        final int numberOfUrls = urlStrings.size();
        int ii = 0;
        for (final String urlString : urlStrings) {
            try {

                ii++;
                final byte[] bytes = get(urlString);
                if (bytes == null) {
                    continue;
                }
                return new DataAndUrl(bytes, urlString);
            } catch (Exception e) {
                if (ii == numberOfUrls) {
                    if (e instanceof DSSException) {
                        throw (DSSException) e;
                    }
                    throw new DSSException(e);
                }
                LOG.warn("Impossible to obtain data using {}", urlString, e);
            }
        }
        return null;
    }

    /**
     * This method is useful only with the cache handling implementation of the {@code DataLoader}.
     *
     * @param url     to access
     * @param refresh if true indicates that the cached data should be refreshed
     * @return {@code byte} array of obtained data
     */
    @Override
    public byte[] get(final String url, final boolean refresh) {
        return get(url);
    }

    private byte[] fileGet(String urlString) {
        try {
            return DSSUtils.toByteArray(new URL(urlString).openStream());
        } catch (IOException e) {
            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    /**
     * This method retrieves data using LDAP protocol.
     * - CRL from given LDAP url, e.g. ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     * - ex URL from AIA ldap://xadessrv.plugtests.net/CN=LevelBCAOK,OU=Plugtests_2015-2016,O=ETSI,C=FR?cACertificate;binary
     *
     * @param urlString
     * @return
     */
    private byte[] ldapGet(final String urlString) {

        final Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, urlString);
        try {

            String attributeName = StringUtils.substringAfterLast(urlString, "?");
            if (StringUtils.isEmpty(attributeName)) {
                // default was CRL
                attributeName = "certificateRevocationList;binary";
            }

            final DirContext ctx = new InitialDirContext(env);
            final Attributes attributes = ctx.getAttributes("");
            final Attribute attribute = attributes.get(attributeName);
            final byte[] ldapBytes = (byte[]) attribute.get();
            if (ldapBytes == null || ldapBytes.length == 0) {
                throw new DSSException("Cannot download CRL from: " + urlString);
            }
            return ldapBytes;
        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    /**
     * This method retrieves data using FTP protocol .
     *
     * @param urlString
     * @return
     */
    protected byte[] ftpGet(final String urlString) {
        return httpGet(urlString);
    }

    /**
     * This method retrieves data using HTTP or HTTPS protocol and 'get' method.
     *
     * @param url to access
     * @return {@code byte} array of obtained data or null
     */
    public byte[] httpGet(final String url) {
        try {
            HttpURLConnection connection;
            try {
                connection = createUrlConnection(url, false);
                connection.connect();
            } catch (IOException e) {
                //because of Microsoft domain enviroment
                if (e.getMessage().contains(Integer.toString(HttpURLConnection.HTTP_PROXY_AUTH))) {
                    AuthCacheValue.setAuthCache(new AuthCacheImpl());
                    Authenticator.setDefault(createAuthenticator(url));
                    connection = createUrlConnection(url, false);

                } else {
                    throw new DSSException(e);
                }
            }

            connection.connect();

            return processResponse(connection);
        } catch (Exception e) {
            throw new DSSException(e);
        } finally {
            resetDefaultJdkHttpProxyingDisabledSchemes();
        }
    }

    @Override
    public byte[] post(final String url, byte[] content) throws DSSException {
        return post(url, content, usePostRequestMethodForPost);
    }

    public byte[] post(final String url, byte[] content, boolean postRequestMethod) throws DSSException {

        LOG.debug("Fetching data via POST from url " + url);

        try {

            if (requestHandler != null) {
                content = requestHandler.handle(content);
            }

            HttpURLConnection connection;
            try {
                connection = createUrlConnection(url, true);
                setupForPost(connection, content, postRequestMethod);
                IOUtils.write(content, connection.getOutputStream());
                if (responseHandler != null) {
                    responseHandler.handle(connection);
                }
                connection.connect();
            } catch (IOException e) {
                //because of Microsoft domain enviroment
                if (e.getMessage().contains(Integer.toString(HttpURLConnection.HTTP_PROXY_AUTH))) {
                    AuthCacheValue.setAuthCache(new AuthCacheImpl());
                    Authenticator.setDefault(createAuthenticator(url));
                    connection = createUrlConnection(url, true);
                    setupForPost(connection, content, postRequestMethod);
                    IOUtils.write(content, connection.getOutputStream());
                } else {
                    throw new DSSException(e);
                }
            }

            if (responseHandler != null) {
                responseHandler.handle(connection);
            }
            connection.connect();

            return processResponse(connection);
        } catch (Exception e) {
            throw new DSSException(e);
        } finally {
            resetDefaultJdkHttpProxyingDisabledSchemes();
        }
    }

    /**
     * Used when the {@code HttpClient} is created.
     *
     * @return the value (millis)
     */
    public int getTimeoutConnection() {
        return timeoutConnection;
    }

    /**
     * Used when the {@code HttpClient} is created.
     *
     * @param timeoutConnection the value (millis)
     */
    public void setTimeoutConnection(final int timeoutConnection) {
        this.timeoutConnection = timeoutConnection;
    }

    /**
     * Used when the {@code HttpClient} is created.
     *
     * @return the value (millis)
     */
    public int getTimeoutSocket() {
        return timeoutSocket;
    }

    /**
     * Used when the {@code HttpClient} is created.
     *
     * @param timeoutSocket the value (millis)
     */
    public void setTimeoutSocket(final int timeoutSocket) {
        this.timeoutSocket = timeoutSocket;
    }

    /**
     * Used when the {@code HttpClient} is created.
     *
     * @return maximum number of connections
     */
    public int getConnectionsMaxTotal() {
        return connectionsMaxTotal;
    }

    /**
     * Used when the {@code HttpClient} is created.
     *
     * @param connectionsMaxTotal maximum number of connections
     */
    public void setConnectionsMaxTotal(int connectionsMaxTotal) {
        this.connectionsMaxTotal = connectionsMaxTotal;
    }

    /**
     * Used when the {@code HttpClient} is created.
     *
     * @return maximum number of connections per one route
     */
    public int getConnectionsMaxPerRoute() {
        return connectionsMaxPerRoute;
    }

    /**
     * Used when the {@code HttpClient} is created.
     *
     * @param connectionsMaxPerRoute maximum number of connections per one route
     */
    public void setConnectionsMaxPerRoute(int connectionsMaxPerRoute) {
        this.connectionsMaxPerRoute = connectionsMaxPerRoute;
    }

    /**
     * @return the contentType
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * This allows to set the content type. Example: Content-Type "application/ocsp-request"
     *
     * @param contentType
     */
    @Override
    public void setContentType(final String contentType) {

        this.contentType = contentType;
    }

    /**
     * @return associated {@code ProxyConfig}
     */
    public ProxyConfig getProxyConfig() {
        return proxyConfig;
    }

    /**
     * @param proxyConfig the proxyConfig to set
     */
    public void setProxyConfig(final ProxyConfig proxyConfig) {
        this.proxyConfig = proxyConfig;
    }

    public boolean isUsePostRequestMethodForPost() {
        return usePostRequestMethodForPost;
    }

    public void setUsePostRequestMethodForPost(boolean usePostRequestMethodForPost) {
        this.usePostRequestMethodForPost = usePostRequestMethodForPost;
    }

    public NativeHTTPConnectionHandler getConnectionHandler() {
        return connectionHandler;
    }

    public void setConnectionHandler(NativeHTTPConnectionHandler connectionHandler) {
        this.connectionHandler = connectionHandler;
    }

    public NativeHTTPRequestHandler getRequestHandler() {
        return requestHandler;
    }

    public void setRequestHandler(NativeHTTPRequestHandler requestHandler) {
        this.requestHandler = requestHandler;
    }

    public NativeHTTPResponseHandler getResponseHandler() {
        return responseHandler;
    }

    public void setResponseHandler(NativeHTTPResponseHandler responseHandler) {
        this.responseHandler = responseHandler;
    }

    /**
     * @param host     host
     * @param port     port
     * @param scheme   scheme
     * @param login    login
     * @param password password
     * @return this for fluent addAuthentication
     */
    public NativeCommonsDataLoader addAuthentication(final String host, final int port, final String scheme, final String login, final String password) {

        final HttpHost httpHost = new HttpHost(host, port, scheme);
        final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(login, password);
        authenticationMap.put(httpHost, credentials);
        return this;
    }

    /**
     * This method allows to propagate the authentication information from the current object.
     *
     * @param commonsDataLoader {@code CommonsDataLoader} to be initialized with authentication information
     */
    public void propagateAuthentication(final NativeCommonsDataLoader commonsDataLoader) {

        for (final Map.Entry<HttpHost, UsernamePasswordCredentials> credentialsEntry : authenticationMap.entrySet()) {

            final HttpHost httpHost = credentialsEntry.getKey();
            final UsernamePasswordCredentials credentials = credentialsEntry.getValue();
            commonsDataLoader.addAuthentication(httpHost.getHostName(), httpHost.getPort(), httpHost.getSchemeName(), credentials.getUserName(), credentials.getPassword());
        }
    }

    public HttpURLConnection createUrlConnection(String url, boolean postRequestMethod) throws Exception {
        URL realUrl = new URL(url);

        Proxy proxy = null;
        URI uri = URI.create(url);
        boolean isHttps = false;
        ProxyProperties proxyProperties = null;
        if ("https".equals(uri.getScheme().toLowerCase())) {
            if(proxyConfig != null && proxyConfig.getHttpsProperties() != null) {
                proxyProperties = proxyConfig.getHttpsProperties();
            }

            isHttps = true;
        } else if(proxyConfig != null && proxyConfig.getHttpProperties() != null) {
            proxyProperties = proxyConfig.getHttpProperties();
        }

        if(proxyProperties != null) {
            if (StringUtils.isNotBlank(proxyProperties.getHost()) && proxyProperties.getPort() > 0) {
                String proxyUrl = proxyProperties.getHost().replaceAll("https?://", "");
                String proxyPort = Integer.toString(proxyProperties.getPort());
                System.setProperty("https.proxyHost", proxyUrl);
                System.setProperty("https.proxyPort", proxyPort);
                System.setProperty("http.proxyHost", proxyUrl);
                System.setProperty("http.proxyPort", proxyPort);
                System.setProperty("ftp.proxyHost", proxyUrl);
                System.setProperty("ftp.proxyPort", proxyPort);
                System.setProperty("java.net.useSystemProxies", "false");
                proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyUrl, proxyProperties.getPort()));
            }
        }

        if(proxy == null) {
            System.getProperties().remove("http.proxyUser");
            System.getProperties().remove("http.proxyPassword");
            System.getProperties().remove("https.proxyUser");
            System.getProperties().remove("https.proxyPassword");
            System.getProperties().remove("ftp.proxyUser");
            System.getProperties().remove("ftp.proxyPassword");
            System.setProperty(JDK_SYSTEM_PROPERTY_HTTPS_PROXY_AUTHENCATION_SCHEMAS, "");
            System.setProperty("java.net.useSystemProxies", "true");

            List<Proxy> proxies = ProxySelector.getDefault().select(new URI(url));
            if(proxies != null) {
                for(Proxy proxyTemp : proxies) {
                    proxy = proxyTemp;
                    break;
                }
            }
        }

        Authenticator.setDefault(createAuthenticator(url));

        HttpURLConnection connection;
        if (proxy == null) {
            connection = (HttpURLConnection) realUrl.openConnection();
        } else {
            connection = (HttpURLConnection) realUrl.openConnection(proxy);
        }
        if (postRequestMethod) {
            connection.setRequestMethod(REQUEST_METHOD_POST);
        }
        connection.setConnectTimeout(timeoutSocket);
        connection.setReadTimeout(timeoutConnection);

        if (isHttps) {
            setAcceptedCertificates((HttpsURLConnection) connection);
        }

        if (StringUtils.isNotBlank(contentType)) {
            connection.setRequestProperty(CONTENT_TYPE, contentType);
        }

        if (connectionHandler != null) {
            connectionHandler.handle(connection);
        }

        return connection;
    }

    public Authenticator createAuthenticator(String url) {
        Authenticator result;

        if (proxyConfig != null) {
            URI uri = URI.create(url);
            ProxyProperties proxyProperties = null;
            if ("https".equals(uri.getScheme().toLowerCase())) {
                proxyProperties = proxyConfig.getHttpsProperties();
            } else {
                proxyProperties = proxyConfig.getHttpProperties();
            }

            if(proxyProperties != null) {
                result = new ProxyAuth(null, StringUtils.trimToEmpty(proxyProperties.getUser()), StringUtils.trimToEmpty(proxyProperties.getPassword()));
            } else {
                result = new ProxyAuth(null, "", "");
            }
        } else {
            //because of Microsoft domain enviroment
            result = new ProxyAuth(null, "", "");
        }

        return result;
    }

    private static class ProxyAuth extends Authenticator {
        private final PasswordAuthentication auth;

        public ProxyAuth(String domain, String user, String password) {
            String username = StringUtils.isNotBlank(domain) ? domain + "\\" + user : user;
            auth = new PasswordAuthentication(username, password.toCharArray());
            System.setProperty("http.proxyUser", username);
            System.setProperty("http.proxyPassword", password);
            System.setProperty("https.proxyUser", username);
            System.setProperty("https.proxyPassword", password);
            System.setProperty("ftp.proxyUser", username);
            System.setProperty("ftp.proxyPassword", password);
        }

        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
            if (getRequestorType().equals(RequestorType.PROXY)) {
                return auth;
            } else {
                return super.getPasswordAuthentication();
            }
        }
    }

    public void setAcceptedCertificates(HttpsURLConnection secureConnection) throws Exception {
        SSLSocketFactory sslSocketFactory = createSSLSocketFactory();
        secureConnection.setSSLSocketFactory(sslSocketFactory);
    }

    private SSLSocketFactory createSSLSocketFactory() throws Exception {
        TrustManager[] byPassTrustManagers = createTrustManagers();
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, byPassTrustManagers, new SecureRandom());
        return sslContext.getSocketFactory();
    }

    private void resetDefaultJdkHttpProxyingDisabledSchemes() {
        if (defaultJdkHttpAuthProxyingDisabledSchemes != null) {
            System.setProperty(JDK_SYSTEM_PROPERTY_HTTPS_PROXY_AUTHENCATION_SCHEMAS, defaultJdkHttpAuthProxyingDisabledSchemes);
        } else {
            System.getProperties().remove(JDK_SYSTEM_PROPERTY_HTTPS_PROXY_AUTHENCATION_SCHEMAS);
        }
    }

    private void setupForPost(HttpURLConnection connection, byte[] content, boolean postRequestMethod) throws ProtocolException {
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.setUseCaches(false);

        connection.setRequestProperty("Content-length", String.valueOf(content.length));
    }

    private byte[] processResponse(HttpURLConnection connection) throws Exception {
        InputStream is = connection.getInputStream();
        int responseCode = connection.getResponseCode();
        byte[] returnedBytes = IOUtils.toByteArray(is);
        if (responseHandler != null) {
            returnedBytes = responseHandler.handle(returnedBytes);
        }

        if (HttpURLConnection.HTTP_OK == responseCode) {
            return returnedBytes;
        } else {
            LOG.error("http response: [code: {}] [message: {}]",
                    responseCode, is != null && is.available() > 0 ? Arrays.toString(IOUtils.toByteArray(is)) : "");
            throw new CommonsDataLoaderException("Can't download content (response code: " + responseCode + ") from url: " + connection.getURL().toString(), responseCode, returnedBytes);
        }
    }

    public String getSslKeystorePath() {
        return sslKeystorePath;
    }

    public void setSslKeystorePath(String sslKeystorePath) {
        this.sslKeystorePath = sslKeystorePath;
    }

    public String getSslKeystoreType() {
        return sslKeystoreType;
    }

    public void setSslKeystoreType(String sslKeystoreType) {
        this.sslKeystoreType = sslKeystoreType;
    }

    public String getSslKeystorePassword() {
        return sslKeystorePassword;
    }

    public void setSslKeystorePassword(String sslKeystorePassword) {
        this.sslKeystorePassword = sslKeystorePassword;
    }

    public String getSslTruststorePath() {
        return sslTruststorePath;
    }

    public void setSslTruststorePath(String sslTruststorePath) {
        this.sslTruststorePath = sslTruststorePath;
    }

    public String getSslTruststoreType() {
        return sslTruststoreType;
    }

    public void setSslTruststoreType(String sslTruststoreType) {
        this.sslTruststoreType = sslTruststoreType;
    }

    public String getSslTruststorePassword() {
        return sslTruststorePassword;
    }

    public void setSslTruststorePassword(String sslTruststorePassword) {
        this.sslTruststorePassword = sslTruststorePassword;
    }

    public boolean isSslTruststoreTrustEverything() {
        return sslTruststoreTrustEverything;
    }

    public void setSslTruststoreTrustEverything(boolean sslTruststoreTrustEverything) {
        this.sslTruststoreTrustEverything = sslTruststoreTrustEverything;
    }

    private TrustManager[] createTrustManagers() {
        try {
            if (StringUtils.isNotBlank(sslTruststorePath) && StringUtils.isNotBlank(sslTruststoreType) && StringUtils.isNotBlank(sslTruststorePassword)) {
                KeyStore trustKeyStore = KeyStore.getInstance(sslTruststoreType);
                trustKeyStore.load(new FileInputStream(sslTruststorePath), sslTruststorePassword.toCharArray());
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustKeyStore);
                return trustManagerFactory.getTrustManagers();
            } else if(sslTruststoreTrustEverything) {
                return new TrustManager[]{new AcceptAllTrustManager()};
            } else {
                return null;
            }
        } catch (Exception e) {
            throw new DSSException(e);
        }
    }

    private KeyManager[] createKeyManagers() {
        try {
            if (StringUtils.isNotBlank(sslKeystorePath) && StringUtils.isNotBlank(sslKeystoreType) && StringUtils.isNotBlank(sslKeystorePassword)) {
                return new KeyManager[] {new DefaultKeyManager(new FileInputStream(sslKeystorePath), sslKeystoreType, sslKeystorePassword)};
            } else {
                return new KeyManager[0];
            }
        } catch (Exception e) {
            throw new DSSException(e);
        }
    }
}