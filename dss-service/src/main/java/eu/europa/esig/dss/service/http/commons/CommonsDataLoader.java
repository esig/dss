/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.service.http.commons;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.exception.DSSDataLoaderMultipleException;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.auth.BasicScheme;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.routing.HttpRoutePlanner;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.io.entity.BufferedHttpEntity;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.reactor.ssl.SSLBufferMode;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.TrustStrategy;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.HostnameVerifier;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringTokenizer;

/**
 * Implementation of DataLoader for any protocol.
 * <p>
 * HTTP and HTTPS: using HttpClient which is more flexible for HTTPS without
 * having to add the certificate to the JVM TrustStore. It takes into account a
 * proxy management through {@code ProxyPreferenceManager}. The authentication
 * is also supported.
 */
public class CommonsDataLoader implements DataLoader {

	private static final long serialVersionUID = -805432648564425522L;

	private static final Logger LOG = LoggerFactory.getLogger(CommonsDataLoader.class);

	/** The default connection timeout (1 minute) */
	private static final Timeout TIMEOUT_CONNECTION = toTimeoutMilliseconds(60000);

	/** The default socket timeout (1 minute) */
	private static final Timeout TIMEOUT_SOCKET = toTimeoutMilliseconds(60000);

	/** The default value of maximum connections in time (20) */
	private static final int CONNECTIONS_MAX_TOTAL = 20;

	/** The default value of maximum connections per route (2) */
	private static final int CONNECTIONS_MAX_PER_ROUTE = 2;

	/** The default connection total time to live (TTL) (1 minute) */
	private static final TimeValue CONNECTION_TIME_TO_LIVE = toTimeValueMilliseconds(60000);

	/** The content-type string */
	private static final String CONTENT_TYPE = "Content-Type";

	/** The content type value */
	protected String contentType;

	/** The proxy configuration */
	private ProxyConfig proxyConfig;

	/** The timeout connection */
	private Timeout timeoutConnection = TIMEOUT_CONNECTION;

	/** The connection request timeout */
	private Timeout timeoutConnectionRequest = TIMEOUT_CONNECTION;

	/** The server response timeout */
	private Timeout timeoutResponse = TIMEOUT_CONNECTION;

	/** The timeout socket */
	private Timeout timeoutSocket = TIMEOUT_SOCKET;

	/** Connection keep alive timeout */
	private TimeValue connectionKeepAlive = CONNECTION_TIME_TO_LIVE;

	/** Maximum connections number in time */
	private int connectionsMaxTotal = CONNECTIONS_MAX_TOTAL;

	/** Maximum connections number per route */
	private int connectionsMaxPerRoute = CONNECTIONS_MAX_PER_ROUTE;

	/** The finite connection total time to live (TTL) */
	private TimeValue connectionTimeToLive = CONNECTION_TIME_TO_LIVE;

	/** Defines if the redirection is enabled */
	private boolean redirectsEnabled = true;

	/** Defines if the default system network properties shall be used */
	private boolean useSystemProperties = false;

	/** Contains rules credentials for authentication to different resources */
	private Map<HostConnection, UserCredentials> authenticationMap;

	/** A list of preferred auth schemes, to be executed in the given order */
	private List<String> targetPreferredAuthSchemes;

	/**
	 * Used SSL protocol
	 */
	private String sslProtocol;

	/**
	 * Keystore for SSL.
	 */
	private DSSDocument sslKeystore;

	/**
	 * Keystore's type.
	 */
	private String sslKeystoreType = KeyStore.getDefaultType();

	/**
	 * Keystore's password.
	 */
	private char[] sslKeystorePassword = new char[]{};

	/**
	 * Defines if the keyStore shall be loaded as a trusted material
	 */
	private boolean loadKeyStoreAsTrustMaterial = false;

	/**
	 * TrustStore for SSL.
	 */
	private DSSDocument sslTruststore;

	/**
	 * Trust store's type
	 */
	private String sslTruststoreType = KeyStore.getDefaultType();

	/**
	 * Truststore's password.
	 */
	private char[] sslTruststorePassword = new char[]{};

	/**
	 * The trust strategy
	 */
	private transient TrustStrategy trustStrategy;

	/**
	 * Array of supported SSL protocols
	 */
	private String[] supportedSSLProtocols;

	/**
	 * Array of supported SSL Cipher Suites
	 */
	private String[] supportedSSLCipherSuites;

	/**
	 * The hostname verifier
	 */
	private transient HostnameVerifier hostnameVerifier = new DefaultHostnameVerifier();

	/**
	 * The connection retry strategy
	 */
	private transient HttpRequestRetryStrategy retryStrategy;

	/**
	 * Defines whether the preemptive basic authentication should be used
	 */
	private boolean preemptiveAuthentication;

	/**
	 * Processes the HTTP client response and returns byte array in case of success
	 * Default: {@code CommonsHttpClientResponseHandler}
	 */
	private transient HttpClientResponseHandler<byte[]> httpClientResponseHandler = new CommonsHttpClientResponseHandler();

	/**
	 * Collection of allowed host names for LDAP get request.
	 * NOTE: if not defined, all host names are allowed.
	 */
	private Collection<String> ldapTrustedHostnames;

	/**
	 * The default constructor for CommonsDataLoader.
	 */
	public CommonsDataLoader() {
		// empty
	}

	/**
	 * The constructor for CommonsDataLoader with defined content-type.
	 *
	 * @param contentType
	 *            The content type of each request
	 */
	public CommonsDataLoader(final String contentType) {
		this.contentType = contentType;
	}

	/**
	 * Gets the connection timeout.
	 *
	 * @return the value (millis)
	 */
	public int getTimeoutConnection() {
		return timeoutConnection.toMillisecondsIntBound();
	}

	/**
	 * Sets the connection timeout in milliseconds.
	 *
	 * A negative value is interpreted as undefined (use system default).
	 *
	 * @param timeoutConnection
	 *            the value (millis)
	 */
	public void setTimeoutConnection(final int timeoutConnection) {
		this.timeoutConnection = toTimeoutMilliseconds(timeoutConnection);
	}

	/**
	 * Gets the connection request timeout.
	 *
	 * @return the value (millis)
	 */
	public int getTimeoutConnectionRequest() {
		return timeoutConnectionRequest.toMillisecondsIntBound();
	}

	/**
	 * Sets the connection request in milliseconds.
	 *
	 * A negative value is interpreted as undefined (use system default).
	 *
	 * @param timeoutConnectionRequest
	 *            the value (millis)
	 */
	public void setTimeoutConnectionRequest(int timeoutConnectionRequest) {
		this.timeoutConnectionRequest = toTimeoutMilliseconds(timeoutConnectionRequest);
	}

	/**
	 * Gets the server response timeout.
	 *
	 * @return the value (millis)
	 */
	public int getTimeoutResponse() {
		return timeoutResponse.toMillisecondsIntBound();
	}

	/**
	 * Sets the server response timeout in milliseconds.
	 *
	 * A negative value is interpreted as undefined (use system default).
	 *
	 * @param timeoutResponse
	 *            the value (millis)
	 */
	public void setTimeoutResponse(int timeoutResponse) {
		this.timeoutResponse = toTimeoutMilliseconds(timeoutResponse);
	}

	/**
	 * Gets the socket timeout.
	 *
	 * @return the value (millis)
	 */
	public int getTimeoutSocket() {
		return timeoutSocket.toMillisecondsIntBound();
	}

	/**
	 * Sets the socket timeout in milliseconds.
	 *
	 * A negative value is interpreted as undefined (use system default).
	 *
	 * @param timeoutSocket
	 *            the value (millis)
	 */
	public void setTimeoutSocket(final int timeoutSocket) {
		this.timeoutSocket = toTimeoutMilliseconds(timeoutSocket);
	}

	/**
	 * Gets the connection keep alive timeout.
	 *
	 * @return the value (millis)
	 */
	public int getConnectionKeepAlive() {
		return connectionKeepAlive.toMillisecondsIntBound();
	}

	/**
	 * Sets the connection keep alive timeout in milliseconds.
	 *
	 * @param connectionKeepAlive
	 *            the value (millis)
	 */
	public void setConnectionKeepAlive(int connectionKeepAlive) {
		this.connectionKeepAlive = toTimeValueMilliseconds(connectionKeepAlive);
	}

	/**
	 * Gets the maximum connections number.
	 *
	 * @return the value (millis)
	 */
	public int getConnectionsMaxTotal() {
		return connectionsMaxTotal;
	}

	/**
	 * Sets the maximum connections number.
	 *
	 * @param connectionsMaxTotal
	 *            maximum number of connections
	 */
	public void setConnectionsMaxTotal(int connectionsMaxTotal) {
		this.connectionsMaxTotal = connectionsMaxTotal;
	}

	/**
	 * Gets the maximum connections number per route.
	 *
	 * @return maximum number of connections per one route
	 */
	public int getConnectionsMaxPerRoute() {
		return connectionsMaxPerRoute;
	}

	/**
	 * Sets the maximum connections number per route.
	 *
	 * @param connectionsMaxPerRoute
	 *            maximum number of connections per one route
	 */
	public void setConnectionsMaxPerRoute(int connectionsMaxPerRoute) {
		this.connectionsMaxPerRoute = connectionsMaxPerRoute;
	}

	/**
	 * Gets the finite connection time to live.
	 *
	 * @return connection time to live (millis)
	 */
	public int getConnectionTimeToLive() {
		return connectionTimeToLive.toMillisecondsIntBound();
	}

	/**
	 * Sets the finite connection total time to live (TTL) in milliseconds.
	 *
	 * @param connectionTimeToLive
	 *            the finite connection time to live (millis)
	 */
	public void setConnectionTimeToLive(int connectionTimeToLive) {
		this.connectionTimeToLive = toTimeValueMilliseconds(connectionTimeToLive);
	}

	/**
	 * Gets if redirect is enabled.
	 *
	 * @return true if http redirects are allowed
	 */
	public boolean isRedirectsEnabled() {
		return redirectsEnabled;
	}

	/**
	 * Sets if redirect should be enabled.
	 *
	 * @param redirectsEnabled
	 *            true if http redirects are allowed
	 */
	public void setRedirectsEnabled(boolean redirectsEnabled) {
		this.redirectsEnabled = redirectsEnabled;
	}

	/**
	 * Gets if the default system network properties shall be used
	 *
	 * @return TRUE if the default system network properties shall be used, FALSE otherwise
	 */
	public boolean isUseSystemProperties() {
		return useSystemProperties;
	}

	/**
	 * Sets if the default system network properties shall be used
	 *
	 * Default: FALSE (system properties are not used)
	 *
	 * NOTE: all other configured property may override the default behavior!
	 *
	 * @param useSystemProperties if the default system network properties shall be used
	 */
	public void setUseSystemProperties(boolean useSystemProperties) {
		this.useSystemProperties = useSystemProperties;
	}

	/**
	 * Gets the content type
	 *
	 * @return the contentType
	 */
	public String getContentType() {
		return contentType;
	}

	@Override
	public void setContentType(final String contentType) {
		this.contentType = contentType;
	}

	/**
	 * Gets the proxy configuration
	 *
	 * @return associated {@code ProxyConfig}
	 */
	public ProxyConfig getProxyConfig() {
		return proxyConfig;
	}

	/**
	 * Sets the proxy configuration
	 *
	 * @param proxyConfig
	 *            the proxyConfig to set
	 */
	public void setProxyConfig(final ProxyConfig proxyConfig) {
		this.proxyConfig = proxyConfig;
	}

	/**
	 * This method sets the SSL protocol to be used
	 *
	 * @param sslProtocol
	 *                    the ssl protocol to be used
	 */
	public void setSslProtocol(String sslProtocol) {
		this.sslProtocol = sslProtocol;
	}

	/**
	 * Sets the SSL KeyStore
	 *
	 * @param sslKeyStore {@link DSSDocument}
	 */
	public void setSslKeystore(DSSDocument sslKeyStore) {
		this.sslKeystore = sslKeyStore;
	}

	/**
	 * Sets if the KeyStore shall be considered as a trust material (used for SSL connection)
	 *
	 * @param loadKeyStoreAsTrustMaterial if the KeyStore shall be considered as a trust material
	 */
	public void setKeyStoreAsTrustMaterial(boolean loadKeyStoreAsTrustMaterial) {
		this.loadKeyStoreAsTrustMaterial = loadKeyStoreAsTrustMaterial;
	}

	/**
	 * Sets the SSL KeyStore type
	 *
	 * @param sslKeystoreType {@link String}
	 */
	public void setSslKeystoreType(String sslKeystoreType) {
		this.sslKeystoreType = sslKeystoreType;
	}

	/**
	 * Sets the KeyStore password. Please note that the password shall be the same for the keystore and
	 * the extraction of a corresponding key.
	 *
	 * @param sslKeystorePassword char array representing the password
	 */
	public void setSslKeystorePassword(char[] sslKeystorePassword) {
		this.sslKeystorePassword = sslKeystorePassword;
	}

	/**
	 * Sets the SSL trust store
	 *
	 * NOTE: different from KeyStore!
	 *
	 * @param sslTrustStore {@link DSSDocument}
	 */
	public void setSslTruststore(DSSDocument sslTrustStore) {
		this.sslTruststore = sslTrustStore;
	}

	/**
	 * Sets the password for SSL truststore
	 *
	 * @param sslTruststorePassword char array representing a password string
	 */
	public void setSslTruststorePassword(char[] sslTruststorePassword) {
		this.sslTruststorePassword = sslTruststorePassword;
	}

	/**
	 * Sets the SSL TrustStore type
	 *
	 * @param sslTruststoreType {@link String}
	 */
	public void setSslTruststoreType(String sslTruststoreType) {
		this.sslTruststoreType = sslTruststoreType;
	}

	/**
	 * Returns the current instance of the authentication map
	 *
	 * @return a map between {@link HostConnection} and {@link UserCredentials}
	 */
	public Map<HostConnection, UserCredentials> getAuthenticationMap() {
		if (authenticationMap == null) {
			authenticationMap = new HashMap<>();
		}
		return authenticationMap;
	}

	/**
	 * Sets the authentication map
	 *
	 * NOTE: this method overrides the current instance of {@code authenticationMap}
	 *
	 * @param authenticationMap a map between {@link HostConnection} and {@link UserCredentials}
	 */
	public void setAuthenticationMap(Map<HostConnection, UserCredentials> authenticationMap) {
		this.authenticationMap = authenticationMap;
	}

	/**
	 * Adds authentication credentials to the existing {@code authenticationMap}
	 *
	 * @param hostConnection
	 *            host connection details
	 * @param userCredentials
	 *            user login credentials
	 * @return this (for fluent addAuthentication)
	 */
	public CommonsDataLoader addAuthentication(HostConnection hostConnection, UserCredentials userCredentials) {
		final Map<HostConnection, UserCredentials> currentAuthenticationMap = getAuthenticationMap();
		currentAuthenticationMap.put(hostConnection, userCredentials);
		return this;
	}

	/**
	 * Adds authentication credentials to the existing {@code authenticationMap}
	 *
	 * @param host
	 *            host
	 * @param port
	 *            port
	 * @param scheme
	 *            scheme
	 * @param login
	 *            login
	 * @param password
	 *            password
	 * @return this (for fluent addAuthentication)
	 */
	public CommonsDataLoader addAuthentication(final String host, final int port, final String scheme,
											   final String login, final char[] password) {
		final HostConnection hostConnection = new HostConnection(host, port, scheme);
		final UserCredentials userCredentials = new UserCredentials(login, password);
		return addAuthentication(hostConnection, userCredentials);
	}

	/**
	 * Gets the target preferred authentication scheme, to be called in the given order
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getTargetPreferredAuthSchemes() {
		return targetPreferredAuthSchemes;
	}

	/**
	 * Sets a list of target preferred authentication schemes,
	 * to be executed on the given order on connection establishing
	 * Default: "Bearer", "Digest", "Basic".
	 *
	 * @param targetPreferredAuthSchemes a list of {@link String}s
	 */
	public void setTargetPreferredAuthSchemes(List<String> targetPreferredAuthSchemes) {
		this.targetPreferredAuthSchemes = targetPreferredAuthSchemes;
	}

	/**
	 * Sets whether the preemptive authentication should be used.
	 * When set to TRUE, the client sends authentication details (i.e. user credentials) within the initial request
	 * to the remote host, instead of sending the credentials only after a request from the host.
	 * Please note that the preemptive authentication should not be used over an insecure connection.
	 * Default : FALSE (preemptive authentication is not used)
	 *
	 * @param preemptiveAuthentication whether the preemptive authentication should be used
	 */
	public void setPreemptiveAuthentication(boolean preemptiveAuthentication) {
		this.preemptiveAuthentication = preemptiveAuthentication;
	}

	/**
	 * Sets a custom retry strategy
	 *
	 * @param retryStrategy {@link HttpRequestRetryStrategy}
	 */
	public void setRetryStrategy(final HttpRequestRetryStrategy retryStrategy) {
		this.retryStrategy = retryStrategy;
	}

	/**
	 * Gets supported SSL protocols
	 *
	 * @return an array if {@link String}s
	 */
	public String[] getSupportedSSLProtocols() {
		return supportedSSLProtocols;
	}

	/**
	 * Sets supported SSL protocols
	 *
	 * @param supportedSSLProtocols an array if {@link String}s
	 */
	public void setSupportedSSLProtocols(String[] supportedSSLProtocols) {
		this.supportedSSLProtocols = supportedSSLProtocols;
	}

	/**
	 * Gets supported SSL Cipher Suites
	 *
	 * @return an array if {@link String}s
	 */
	public String[] getSupportedSSLCipherSuites() {
		return supportedSSLCipherSuites;
	}

	/**
	 * Sets supported SSL Cipher Suites
	 *
	 * @param supportedSSLCipherSuites an array if {@link String}s
	 */
	public void setSupportedSSLCipherSuites(String[] supportedSSLCipherSuites) {
		this.supportedSSLCipherSuites = supportedSSLCipherSuites;
	}

	/**
	 * Gets the hostname verifier
	 *
	 * @return {@link HostnameVerifier}
	 */
	public HostnameVerifier getHostnameVerifier() {
		return hostnameVerifier;
	}

	/**
	 * Sets a custom {@code HostnameVerifier}
	 *
	 * @param hostnameVerifier {@link HostnameVerifier}
	 */
	public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
		this.hostnameVerifier = hostnameVerifier;
	}

	/**
	 * Gets the TrustStrategy
	 *
	 * @return {@link TrustStrategy}
	 */
	public TrustStrategy getTrustStrategy() {
		return trustStrategy;
	}

	/**
	 * Sets the {@code TrustStrategy}
	 *
	 * @param trustStrategy {@link TrustStrategy}
	 */
	public void setTrustStrategy(TrustStrategy trustStrategy) {
		this.trustStrategy = trustStrategy;
	}

	/**
	 * Returns the {@code HttpClientResponseHandler} response handler
	 *
	 * @return {@link HttpClientResponseHandler}
	 */
	public HttpClientResponseHandler<byte[]> getHttpClientResponseHandler() {
		return httpClientResponseHandler;
	}

	/**
	 * Sets the {@code HttpClientResponseHandler<byte[]>} response handler performing a processing of
	 * an HTTP client response and returns a byte array in case of success.
	 *
	 * @param httpClientResponseHandler {@link HttpClientResponseHandler}
	 */
	public void setHttpClientResponseHandler(HttpClientResponseHandler<byte[]> httpClientResponseHandler) {
		Objects.requireNonNull(httpClientResponseHandler, "HttpClientResponseHandler cannot be null!");
		this.httpClientResponseHandler = httpClientResponseHandler;
	}

	/**
	 * Sets a collection of allowed host names to perform an LDAP get request.
	 * The name of the host shall be defined in the complete form corresponding to the full domain name extracted
	 * from an extracted LDAP URL.
	 * E.g. "ldap.infonotary.com" for LDAP URL "ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com".
	 * NOTE: when not defined, all LDAP URLs will be accepted.
	 *
	 * @param ldapTrustedHostnames a collection of allowed host name {@link String}s
	 */
	public void setLdapTrustedHostnames(Collection<String> ldapTrustedHostnames) {
		this.ldapTrustedHostnames = ldapTrustedHostnames;
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
			LOG.warn("DSS framework only supports FILE, HTTP, HTTPS, FTP and LDAP Urls.");
		}
		return httpGet(urlString);
	}

	@Override
	public DataAndUrl get(final List<String> urlStrings) {
		if (Utils.isCollectionEmpty(urlStrings)) {
			throw new DSSExternalResourceException("Cannot process the GET call. List of URLs is empty!");
		}

		final Map<String, Throwable> exceptions = new HashMap<>(); // store map of exception thrown for urls
		for (String urlString : urlStrings) {
			LOG.debug("Processing a GET call to URL [{}]...", urlString);
			try {
				final byte[] bytes = get(urlString);
				if (Utils.isArrayEmpty(bytes)) {
					LOG.debug("The retrieved content from URL [{}] is empty. Continue with other URLs...", urlString);
					continue;
				}
				return new DataAndUrl(urlString, bytes);
			} catch (Exception e) {
				LOG.warn("Cannot obtain data using '{}' : {}", urlString, e.getMessage());
				exceptions.put(urlString, e);
			}
		}
		throw new DSSDataLoaderMultipleException(exceptions);
	}

	/**
	 * This method retrieves data using LDAP protocol. - CRL from given LDAP
	 * url, e.g. ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
	 * - ex URL from AIA
	 * ldap://xadessrv.plugtests.net/CN=LevelBCAOK,OU=Plugtests_2015-2016,O=ETSI,C=FR?cACertificate;binary
	 *
	 * @param urlString {@link String}
	 * @return byte array
	 */
	protected byte[] ldapGet(String urlString) {
		String host = LdapURLUtils.getHost(urlString);
		if (ldapTrustedHostnames != null && !ldapTrustedHostnames.contains(host)) {
			throw new DSSExternalResourceException(String.format(
					"Cannot get data from URL [%s]. Reason : [Untrusted host name '%s']", urlString, host));
		}

		urlString = LdapURLUtils.encode(urlString);

		final Hashtable<String, String> env = initLdapContextEnvironment();
		env.put(Context.PROVIDER_URL, urlString);

		try {

			// parse URL according to the template: 'ldap://host:port/DN?attributes?scope?filter?extensions'
			String ldapParams = Utils.substringAfter(urlString, "?");
			StringTokenizer tokenizer = new StringTokenizer(ldapParams, "?");
			String attributeName = (tokenizer.hasMoreTokens()) ? tokenizer.nextToken() : null;

			if (Utils.isStringEmpty(attributeName)) {
				// default was CRL
				attributeName = "certificateRevocationList;binary";
			}

			final DirContext ctx = new InitialDirContext(env);
			final Attributes attributes = ctx.getAttributes(Utils.EMPTY_STRING, new String[] { attributeName });
			if ((attributes == null) || (attributes.size() < 1)) {
				throw new DSSExternalResourceException(String.format("Cannot download binaries from: [%s], no attributes with name: [%s] returned", urlString, attributeName));
			} else {
				final Attribute attribute = attributes.getAll().next();
				final byte[] ldapBytes = (byte[]) attribute.get();
				if (Utils.isArrayNotEmpty(ldapBytes)) {
					return ldapBytes;
				}
				throw new DSSExternalResourceException(String.format("The retrieved ldap content from url [%s] is empty", urlString));
			}
		} catch (DSSExternalResourceException e) {
			throw e;
		} catch (Exception e) {
			throw new DSSExternalResourceException(String.format("Cannot get data from URL [%s]. Reason : [%s]", urlString, e.getMessage()), e);
		}
	}

	/**
	 * Creates an LDAP Context environment
	 *
	 * @return {@link Hashtable} containing a list of properties for the LDAP environment
	 */
	protected Hashtable<String, String> initLdapContextEnvironment() {
		final Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		return env;
	}

	/**
	 * This method retrieves data using FTP protocol .
	 *
	 * @param urlString {@link String} url to retrieve data from
	 * @return byte array
	 */
	protected byte[] ftpGet(final String urlString) {
		final URL url = getURL(urlString);
		try (InputStream inputStream = url.openStream()) {
			return DSSUtils.toByteArray(inputStream);
		} catch (IOException e) {
			throw new DSSExternalResourceException(String.format("Unable to retrieve file from URL %s. Reason : [%s]", urlString, e.getMessage()), e);
		}
	}

	/**
	 * Gets the file content by its URL
	 *
	 * @param urlString {@link String} to the file
	 * @return byte array of the file content
	 */
	protected byte[] fileGet(final String urlString) {
		return ftpGet(urlString);
	}

	private URL getURL(String urlString) {
		try {
			return URI.create(urlString).toURL();
		} catch (MalformedURLException | IllegalArgumentException e) {
			throw new DSSExternalResourceException("Unable to create URL instance", e);
		}
	}

	/**
	 * This method retrieves data using HTTP or HTTPS protocol and 'get' method.
	 *
	 * @param url
	 *            to access
	 * @return {@code byte} array of obtained data or null
	 */
	protected byte[] httpGet(final String url) {

		HttpGet httpRequest = null;
		CloseableHttpClient client = null;

		try {
			httpRequest = getHttpRequest(url);
			client = getHttpClient(url);
			return execute(client, httpRequest);

		} catch (URISyntaxException | IOException e) {
			throw new DSSExternalResourceException(String.format("Unable to process GET call for url [%s]. Reason : [%s]", url, DSSUtils.getExceptionMessage(e)), e);

		} finally {
			closeQuietly(httpRequest, client);

		}
	}

	@Override
	public byte[] post(final String url, final byte[] content) {
		LOG.debug("Fetching data via POST from url {}", url);

		final URI uri = URI.create(Utils.trim(url));
		HttpPost httpRequest = new HttpPost(uri);
		CloseableHttpClient client = null;

		// The length for the InputStreamEntity is needed, because some receivers (on the other side)
		// need this information.
		// To determine the length, we cannot read the content-stream up to the end and re-use it afterwards.
		// This is because, it may not be possible to reset the stream (= go to position 0).
		// So, the solution is to cache temporarily the complete content data (as we do not expect much here) in
		// a byte-array.
		try (final ByteArrayInputStream bis = new ByteArrayInputStream(content);
			 final HttpEntity httpEntity = new InputStreamEntity(bis, content.length, toContentType(contentType));
			 final HttpEntity requestEntity = new BufferedHttpEntity(httpEntity)) {

			httpRequest.setEntity(requestEntity);

			client = getHttpClient(url);
			return execute(client, httpRequest);

		} catch (IOException e) {
			throw new DSSExternalResourceException(String.format("Unable to process POST call for url [%s]. Reason : [%s]", url, e.getMessage()) , e);

		} finally {
			closeQuietly(httpRequest, client);
		}
	}

	/**
	 * Processes {@code httpRequest} and returns the byte array representing the response's content
	 *
	 * @param client {@link CloseableHttpClient}
	 * @param httpRequest {@link HttpUriRequest}
	 * @return byte array representing the response's content
	 * @throws IOException if an exception occurs
	 */
	protected byte[] execute(final CloseableHttpClient client, final HttpUriRequest httpRequest) throws IOException {
		final HttpHost targetHost = getHttpHost(httpRequest);
		final HttpContext localContext = getHttpContext(targetHost);
		final HttpClientResponseHandler<byte[]> responseHandler = getHttpClientResponseHandler();
		return client.execute(targetHost, httpRequest, localContext, responseHandler);
	}

	/**
	 * Gets the {@code HttpHost}
	 *
	 * @param httpRequest {@link HttpUriRequest}
	 * @return {@link HttpHost}
	 */
	protected HttpHost getHttpHost(final HttpUriRequest httpRequest) {
		try {
			final URI uri = httpRequest.getUri();
			return new HttpHost(uri.getScheme(), uri.getHost(), uri.getPort());
		} catch (URISyntaxException e) {
			throw new DSSExternalResourceException(String.format("Invalid URI : %s", e.getMessage()), e);
		}
	}

	/**
	 * Gets the {@code HttpContext}
	 *
	 * @param httpHost {@link HttpHost}
	 * @return {@link HttpContext}
	 */
	protected HttpContext getHttpContext(HttpHost httpHost) {
		HttpClientContext localContext = HttpClientContext.create();
		localContext = configurePreemptiveAuthentication(localContext, httpHost);
		return localContext;
	}

	/**
	 * This method is used to configure preemptive authentication process for {@code HttpClientContext}, when required
	 *
	 * @param localContext {@link HttpClientContext}
	 * @param httpHost {@link HttpHost}
	 * @return {@link HttpClientContext}
	 */
	protected HttpClientContext configurePreemptiveAuthentication(HttpClientContext localContext, HttpHost httpHost) {
		if (preemptiveAuthentication && Utils.isMapNotEmpty(getAuthenticationMap())) {
			Credentials credentials = getCredentialsProvider().getCredentials(new AuthScope(httpHost), localContext);
			BasicScheme basicScheme = new BasicScheme();
			basicScheme.initPreemptive(credentials);
			localContext.resetAuthExchange(httpHost, basicScheme);
		}
		return localContext;
	}

	/**
	 * Closes all the parameters quietly
	 *
	 * @param httpRequest {@link HttpUriRequestBase}
	 * @param client {@link CloseableHttpClient}
	 */
	protected void closeQuietly(HttpUriRequestBase httpRequest, CloseableHttpClient client) {
		try {
			if (httpRequest != null) {
				httpRequest.cancel();
			}
		} finally {
			Utils.closeQuietly(client);
		}
	}

	/**
	 * Gets a configured {@code HttpClientConnectionManager}
	 *
	 * @return {@link HttpClientConnectionManager}
	 */
	protected HttpClientConnectionManager getConnectionManager() {
		final PoolingHttpClientConnectionManagerBuilder builder = PoolingHttpClientConnectionManagerBuilder.create()
				.setTlsSocketStrategy(getTlsSocketStrategy())
				.setDefaultSocketConfig(getSocketConfig())
				.setMaxConnTotal(getConnectionsMaxTotal())
				.setMaxConnPerRoute(getConnectionsMaxPerRoute());

		final ConnectionConfig.Builder connectionConfigBuilder = ConnectionConfig.custom()
				.setConnectTimeout(timeoutConnection)
				.setTimeToLive(connectionTimeToLive);

		final PoolingHttpClientConnectionManager connectionManager = builder.build();
		connectionManager.setDefaultConnectionConfig(connectionConfigBuilder.build());

		LOG.debug("PoolingHttpClientConnectionManager: max total: {}", connectionManager.getMaxTotal());
		LOG.debug("PoolingHttpClientConnectionManager: max per route: {}", connectionManager.getDefaultMaxPerRoute());

		return connectionManager;
	}

	/**
	 * Gets a configured {@code SocketConfig}
	 *
	 * @return {@link SocketConfig}
	 */
	protected SocketConfig getSocketConfig() {
		SocketConfig.Builder socketConfigBuilder = SocketConfig.custom();
		socketConfigBuilder.setSoTimeout(timeoutSocket);
		return socketConfigBuilder.build();
	}

	/**
	 * Gets a configured {@code SSLContextBuilder} containing an SSL connection trust configuration
	 *
	 * @return {@link SSLContextBuilder}
	 */
	protected SSLContextBuilder getSSLContextBuilder() {
		try {
			SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();
			sslContextBuilder.setProtocol(sslProtocol);

			if (trustStrategy != null) {
				LOG.debug("Set the TrustStrategy");
				sslContextBuilder.loadTrustMaterial(null, trustStrategy);
			}

			final KeyStore sslTrustStore = getSSLTrustStore();
			if (sslTrustStore != null) {
				LOG.debug("Set the SSL trust store as trust materials");
				sslContextBuilder.loadTrustMaterial(sslTrustStore, trustStrategy);
			}

			final KeyStore sslKeyStore = getSSLKeyStore();
			if (sslKeyStore != null) {
				LOG.debug("Set the SSL keystore as key materials");
				sslContextBuilder.loadKeyMaterial(sslKeyStore, sslKeystorePassword);
				if (loadKeyStoreAsTrustMaterial) {
					LOG.debug("Set the SSL keystore as trust materials");
					sslContextBuilder.loadTrustMaterial(sslKeyStore, trustStrategy);
				}
			}
			return sslContextBuilder;
		} catch (final Exception e) {
			throw new IllegalArgumentException("Unable to configure the SSLContext", e);
		}
	}

	/**
	 * Gets a configured {@code TlsSocketStrategy}
	 *
	 * @return {@link TlsSocketStrategy}
	 */
	protected TlsSocketStrategy getTlsSocketStrategy() {
		try {
			return new DefaultClientTlsStrategy(getSSLContextBuilder().build(), getSupportedSSLProtocols(),
					getSupportedSSLCipherSuites(), SSLBufferMode.STATIC, getHostnameVerifier());
		} catch (final Exception e) {
			throw new IllegalArgumentException("Unable to configure the TLSSocketStrategy", e);
		}
	}

	/**
	 * Gets the SSL KeyStore
	 *
	 * @return {@link KeyStore}
	 * @throws IOException if IOException occurs
	 * @throws GeneralSecurityException if GeneralSecurityException occurs
	 */
	protected KeyStore getSSLKeyStore() throws IOException, GeneralSecurityException {
		return loadKeyStore(sslKeystore, sslKeystoreType, sslKeystorePassword);
	}

	/**
	 * Gets the SSL Trusted KeyStore
	 *
	 * @return {@link KeyStore}
	 * @throws IOException if IOException occurs
	 * @throws GeneralSecurityException if GeneralSecurityException occurs
	 */
	protected KeyStore getSSLTrustStore() throws IOException, GeneralSecurityException {
		return loadKeyStore(sslTruststore, sslTruststoreType, sslTruststorePassword);
	}

	private KeyStore loadKeyStore(DSSDocument store, String type, char[] password) throws IOException, GeneralSecurityException {
		if (store != null) {
			try (InputStream is = store.openStream()) {
				KeyStore ks = KeyStore.getInstance(type);
				ks.load(is, password);
				return ks;
			}
		} else {
			return null;
		}
	}

	/**
	 * Gets the HTTP request
	 *
	 * @param url {@link String} request url
	 * @return {@link HttpGet}
	 * @throws URISyntaxException if an exception occurs
	 */
	protected synchronized HttpGet getHttpRequest(String url) throws URISyntaxException {
		final URI uri = new URI(Utils.trim(url));
		HttpGet httpRequest = new HttpGet(uri);
		if (contentType != null) {
			httpRequest.setHeader(CONTENT_TYPE, contentType);
		}
		return httpRequest;
	}

	/**
	 * Gets the {@code HttpClientBuilder} for the url
	 *
	 * @param url {@link String} request url
	 * @return {@link HttpClientBuilder}
	 */
	protected synchronized HttpClientBuilder getHttpClientBuilder(final String url) {
		HttpClientBuilder httpClientBuilder = HttpClients.custom();

		if (useSystemProperties) {
			httpClientBuilder.useSystemProperties();
		}

		httpClientBuilder = configCredentials(httpClientBuilder, url);

		httpClientBuilder.setConnectionManager(getConnectionManager())
				.setDefaultRequestConfig(getRequestConfig())
				.setRetryStrategy(retryStrategy);
		
		return httpClientBuilder;
	}

	/**
	 * Gets the HTTP client
	 *
	 * @param url {@link String} request url
	 * @return {@link CloseableHttpClient}
	 */
	protected synchronized CloseableHttpClient getHttpClient(final String url) {
		return getHttpClientBuilder(url).build();
	}

	/**
	 * Gets a configured {@code RequestConfig.Builder}
	 *
	 * @return {@link RequestConfig.Builder}
	 */
	protected RequestConfig.Builder getRequestConfigBuilder() {
		return RequestConfig.custom()
				.setTargetPreferredAuthSchemes(targetPreferredAuthSchemes)
				.setConnectionRequestTimeout(timeoutConnectionRequest)
				.setResponseTimeout(timeoutResponse)
				.setConnectionKeepAlive(connectionKeepAlive)
				.setRedirectsEnabled(redirectsEnabled);
	}

	/**
	 * Builds and gets a {@code RequestConfig}
	 *
	 * @return {@link RequestConfig}
	 */
	protected RequestConfig getRequestConfig() {
		return getRequestConfigBuilder().build();
	}

	/**
	 * Defines the Credentials
	 *
	 * @param httpClientBuilder {@link HttpClientBuilder}
	 * @param url {@link String}
	 * @return {@link HttpClientBuilder}
	 */
	private HttpClientBuilder configCredentials(HttpClientBuilder httpClientBuilder, final String url) {
		final BasicCredentialsProvider credentialsProvider = getCredentialsProvider();
		httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
		httpClientBuilder = configureProxy(httpClientBuilder, credentialsProvider, url);
		return httpClientBuilder;
	}

	/**
	 * Builds and returns a {@code BasicCredentialsProvider} configured with {@code authenticationMap}
	 *
	 * @return {@link BasicCredentialsProvider}
	 */
	protected BasicCredentialsProvider getCredentialsProvider() {
		final BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		for (final Map.Entry<HostConnection, UserCredentials> entry : getAuthenticationMap().entrySet()) {
			final HostConnection hostConnection = entry.getKey();
			final UserCredentials userCredentials = entry.getValue();
			final AuthScope authscope = new AuthScope(hostConnection.getProtocol(),
					hostConnection.getHost(), hostConnection.getPort(),
					hostConnection.getRealm(), hostConnection.getScheme());

			final UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(
					userCredentials.getUsername(), userCredentials.getPassword());
			credentialsProvider.setCredentials(authscope, usernamePasswordCredentials);
		}
		return credentialsProvider;
	}

	/**
	 * Configure the proxy with the required credential if needed
	 *
	 * @param httpClientBuilder {@link HttpClientBuilder}
	 * @param credentialsProvider {@link BasicCredentialsProvider}
	 * @param url {@link String}
	 * @return {@link HttpClientBuilder}
	 */
	private HttpClientBuilder configureProxy(HttpClientBuilder httpClientBuilder,
											 BasicCredentialsProvider credentialsProvider, String url) {
		if (proxyConfig == null) {
			return httpClientBuilder;
		}

		final String protocol = getURL(url).getProtocol();
		final boolean proxyHTTPS = Protocol.isHttps(protocol) && (proxyConfig.getHttpsProperties() != null);
		final boolean proxyHTTP = Protocol.isHttp(protocol) && (proxyConfig.getHttpProperties() != null);

		ProxyProperties proxyProps;
		if (proxyHTTPS) {
			LOG.debug("Use proxy https parameters");
			proxyProps = proxyConfig.getHttpsProperties();
		} else if (proxyHTTP) {
			LOG.debug("Use proxy http parameters");
			proxyProps = proxyConfig.getHttpProperties();
		} else {
			return httpClientBuilder;
		}

		String scheme = proxyProps.getScheme();
		String proxyHost = proxyProps.getHost();
		int proxyPort = proxyProps.getPort();
		String proxyUser = proxyProps.getUser();
		char[] proxyPassword = proxyProps.getPassword();
		Collection<String> excludedHosts = proxyProps.getExcludedHosts();

		if (Utils.isStringNotEmpty(proxyUser) && Utils.isArrayNotEmpty(proxyPassword)) {
			AuthScope proxyAuth = new AuthScope(proxyHost, proxyPort);
			UsernamePasswordCredentials proxyCredentials = new UsernamePasswordCredentials(
					proxyUser, proxyPassword);
			credentialsProvider.setCredentials(proxyAuth, proxyCredentials);
		}

		LOG.debug("proxy host/port: {}:{}", proxyHost, proxyPort);
		final HttpHost proxy = new HttpHost(scheme, proxyHost, proxyPort);

		if (Utils.isCollectionNotEmpty(excludedHosts)) {

			final HttpRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy) {

				@Override
				protected HttpHost determineProxy(HttpHost host, HttpContext context) throws HttpException {
					String hostname = (host != null ? host.getHostName().toLowerCase() : null);
					if (hostname != null) {
						for (String h : excludedHosts) {
							String hostnamePattern = h.toLowerCase();
							if (hostname.equals(hostnamePattern)) {
								// bypass proxy for that hostname
								return null;

							} else if (hostnamePattern.equals("*")) {
								// bypass all hostnames
								return null;

							} else if (hostnamePattern.startsWith("*.")) {
								String matchingEnd = hostnamePattern.substring(1).toLowerCase();
								if (hostname.endsWith(matchingEnd)) {
									// pattern matches, bypass proxy for that hostname
									return null;
								}
							}
						}
					}
					return super.determineProxy(host, context);
				}

			};

			httpClientBuilder.setRoutePlanner(routePlanner);
		}

		return httpClientBuilder.setProxy(proxy);
	}

	private static Timeout toTimeoutMilliseconds(int millis) {
		if (millis < 0) {
			LOG.info("A negative timeout has been provided. Use system default.");
			return null;
		}
		return Timeout.ofMilliseconds(millis);
	}

	private static TimeValue toTimeValueMilliseconds(int millis) {
		return TimeValue.ofMilliseconds(millis);
	}

	private static ContentType toContentType(String contentTypeString) {
		return Utils.isStringNotBlank(contentTypeString) ? ContentType.create(contentTypeString) : null;
	}

}
