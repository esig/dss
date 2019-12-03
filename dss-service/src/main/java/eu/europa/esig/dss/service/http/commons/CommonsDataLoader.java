/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.service.http.commons;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.HostnameVerifier;

import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.ServiceUnavailableRetryStrategy;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.exception.DSSDataLoaderMultipleException;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;

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

	private static final int TIMEOUT_CONNECTION = 6000;

	private static final int TIMEOUT_SOCKET = 6000;

	private static final int CONNECTIONS_MAX_TOTAL = 20;

	private static final int CONNECTIONS_MAX_PER_ROUTE = 2;

	private static final String CONTENT_TYPE = "Content-Type";

	private static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";

	private static final List<Integer> ACCEPTED_HTTP_STATUS = Arrays.asList(HttpStatus.SC_OK);

	protected String contentType;

	private ProxyConfig proxyConfig;

	private int timeoutConnection = TIMEOUT_CONNECTION;
	private int timeoutSocket = TIMEOUT_SOCKET;
	private int connectionsMaxTotal = CONNECTIONS_MAX_TOTAL;
	private int connectionsMaxPerRoute = CONNECTIONS_MAX_PER_ROUTE;
	private boolean redirectsEnabled = true;
	private List<Integer> acceptedHttpStatus = ACCEPTED_HTTP_STATUS;

	private final Map<HttpHost, UsernamePasswordCredentials> authenticationMap = new HashMap<HttpHost, UsernamePasswordCredentials>();

	/**
	 * Used SSL protocol
	 */
	private String sslProtocol = DEFAULT_SSL_PROTOCOL;

	/**
	 * Path to the keystore.
	 */
	private String sslKeystorePath;

	/**
	 * Keystore's type.
	 */
	private String sslKeystoreType = KeyStore.getDefaultType();
	/**
	 * Keystore's password.
	 */
	private String sslKeystorePassword = Utils.EMPTY_STRING;
	/**
	 *
	 */
	private boolean loadKeyStoreAsTrustMaterial = false;

	/**
	 * Path to the truststore.
	 */
	private String sslTruststorePath;
	/**
	 * Trust store's type
	 */
	private String sslTruststoreType = KeyStore.getDefaultType();
	/**
	 * Truststore's password.
	 */
	private String sslTruststorePassword = Utils.EMPTY_STRING;

	private TrustStrategy trustStrategy;

	private String[] supportedSSLProtocols;

	private String[] supportedSSLCipherSuites;

	private HostnameVerifier hostnameVerifier = SSLConnectionSocketFactory.getDefaultHostnameVerifier();

	private HttpRequestRetryHandler retryHandler;

	private ServiceUnavailableRetryStrategy serviceUnavailableRetryStrategy;

	/**
	 * The default constructor for CommonsDataLoader.
	 */
	public CommonsDataLoader() {
		this(null);
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

	private HttpClientConnectionManager getConnectionManager() {

		RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder = RegistryBuilder.create();
		socketFactoryRegistryBuilder = setConnectionManagerSchemeHttp(socketFactoryRegistryBuilder);
		socketFactoryRegistryBuilder = setConnectionManagerSchemeHttps(socketFactoryRegistryBuilder);

		final PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistryBuilder.build());

		connectionManager.setMaxTotal(getConnectionsMaxTotal());
		connectionManager.setDefaultMaxPerRoute(getConnectionsMaxPerRoute());

		LOG.debug("PoolingHttpClientConnectionManager: max total: {}", connectionManager.getMaxTotal());
		LOG.debug("PoolingHttpClientConnectionManager: max per route: {}", connectionManager.getDefaultMaxPerRoute());

		return connectionManager;
	}

	private RegistryBuilder<ConnectionSocketFactory> setConnectionManagerSchemeHttp(RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder) {
		return socketFactoryRegistryBuilder.register("http", PlainConnectionSocketFactory.getSocketFactory());
	}

	private RegistryBuilder<ConnectionSocketFactory> setConnectionManagerSchemeHttps(
			final RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder) {
		try {

			SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();
			sslContextBuilder.setProtocol(sslProtocol);

			final KeyStore sslTrustStore = getSSLTrustStore();
			if (sslTrustStore != null) {
				LOG.debug("Set the SSL trust store as trust materials");
				sslContextBuilder.loadTrustMaterial(sslTrustStore, getTrustStrategy());
			}

			final KeyStore sslKeystore = getSSLKeyStore();
			if (sslKeystore != null) {
				LOG.debug("Set the SSL keystore as key materials");
				final char[] password = sslKeystorePassword != null ? sslKeystorePassword.toCharArray() : null;
				sslContextBuilder.loadKeyMaterial(sslKeystore, password);
				if (loadKeyStoreAsTrustMaterial) {
					LOG.debug("Set the SSL keystore as trust materials");
					sslContextBuilder.loadTrustMaterial(sslKeystore, getTrustStrategy());
				}
			}

			SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContextBuilder.build(), getSupportedSSLProtocols(),
					getSupportedSSLCipherSuites(), getHostnameVerifier());
			return socketFactoryRegistryBuilder.register("https", sslConnectionSocketFactory);
		} catch (final Exception e) {
			throw new DSSException("Unable to configure the SSLContext/SSLConnectionSocketFactory", e);
		}
	}

	protected KeyStore getSSLKeyStore() throws IOException, GeneralSecurityException {
		return loadKeyStore(sslKeystorePath, sslKeystoreType, sslKeystorePassword);
	}

	protected KeyStore getSSLTrustStore() throws IOException, GeneralSecurityException {
		return loadKeyStore(sslTruststorePath, sslTruststoreType, sslTruststorePassword);
	}

	private KeyStore loadKeyStore(String path, String type, String passwordStr) throws IOException, GeneralSecurityException {
		if (Utils.isStringNotEmpty(path)) {
			try (InputStream is = new FileInputStream(path)) {
				KeyStore ks = KeyStore.getInstance(type);
				final char[] password = passwordStr != null ? passwordStr.toCharArray() : null;
				ks.load(is, password);
				return ks;
			}
		} else {
			return null;
		}
	}

	protected synchronized HttpClientBuilder getHttpClientBuilder() {
		return HttpClients.custom();
	}

	protected synchronized CloseableHttpClient getHttpClient(final String url) {
		HttpClientBuilder httpClientBuilder = getHttpClientBuilder();

		httpClientBuilder = configCredentials(httpClientBuilder, url);

		final RequestConfig.Builder custom = RequestConfig.custom();
		custom.setSocketTimeout(timeoutSocket);
		custom.setConnectTimeout(timeoutConnection);
		custom.setRedirectsEnabled(redirectsEnabled);

		final RequestConfig requestConfig = custom.build();
		httpClientBuilder = httpClientBuilder.setDefaultRequestConfig(requestConfig);
		httpClientBuilder.setConnectionManager(getConnectionManager());

		httpClientBuilder.setRetryHandler(retryHandler);
		httpClientBuilder.setServiceUnavailableRetryStrategy(serviceUnavailableRetryStrategy);

		return httpClientBuilder.build();
	}

	/**
	 * Define the Credentials
	 *
	 * @param httpClientBuilder
	 * @param url
	 * @return {@link HttpClientBuilder}
	 */
	private HttpClientBuilder configCredentials(HttpClientBuilder httpClientBuilder, final String url) {

		final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		for (final Map.Entry<HttpHost, UsernamePasswordCredentials> entry : authenticationMap.entrySet()) {

			final HttpHost httpHost = entry.getKey();
			final UsernamePasswordCredentials usernamePasswordCredentials = entry.getValue();
			final AuthScope authscope = new AuthScope(httpHost.getHostName(), httpHost.getPort());
			credentialsProvider.setCredentials(authscope, usernamePasswordCredentials);
		}
		httpClientBuilder = httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
		httpClientBuilder = configureProxy(httpClientBuilder, credentialsProvider, url);
		return httpClientBuilder;
	}

	/**
	 * Configure the proxy with the required credential if needed
	 *
	 * @param httpClientBuilder
	 * @param credentialsProvider
	 * @param url
	 * @return {@link HttpClientBuilder}
	 */
	private HttpClientBuilder configureProxy(HttpClientBuilder httpClientBuilder, CredentialsProvider credentialsProvider, String url) {
		if (proxyConfig == null) {
			return httpClientBuilder;
		}

		final String protocol = getURL(url).getProtocol();
		final boolean proxyHTTPS = Protocol.isHttps(protocol) && (proxyConfig.getHttpsProperties() != null);
		final boolean proxyHTTP = Protocol.isHttp(protocol) && (proxyConfig.getHttpProperties() != null);

		ProxyProperties proxyProps = null;
		if (proxyHTTPS) {
			LOG.debug("Use proxy https parameters");
			proxyProps = proxyConfig.getHttpsProperties();
		} else if (proxyHTTP) {
			LOG.debug("Use proxy http parameters");
			proxyProps = proxyConfig.getHttpProperties();
		} else {
			return httpClientBuilder;
		}

		String proxyHost = proxyProps.getHost();
		int proxyPort = proxyProps.getPort();
		String proxyUser = proxyProps.getUser();
		String proxyPassword = proxyProps.getPassword();
		String proxyExcludedHosts = proxyProps.getExcludedHosts();

		if (Utils.isStringNotEmpty(proxyUser) && Utils.isStringNotEmpty(proxyPassword)) {
			AuthScope proxyAuth = new AuthScope(proxyHost, proxyPort);
			UsernamePasswordCredentials proxyCredentials = new UsernamePasswordCredentials(proxyUser, proxyPassword);
			credentialsProvider.setCredentials(proxyAuth, proxyCredentials);
		}

		LOG.debug("proxy host/port: {}:{}", proxyHost, proxyPort);
		// TODO SSL peer shut down incorrectly when protocol is https
		final HttpHost proxy = new HttpHost(proxyHost, proxyPort, Protocol.HTTP.getName());

		if (Utils.isStringNotEmpty(proxyExcludedHosts)) {
			final String[] hosts = proxyExcludedHosts.split("[,; ]");

			HttpRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy) {
				@Override
				public HttpRoute determineRoute(final HttpHost host, final HttpRequest request, final HttpContext context) throws HttpException {

					String hostname = (host != null ? host.getHostName() : null);

					if ((hosts != null) && (hostname != null)) {
						for (String h : hosts) {
							if (hostname.equalsIgnoreCase(h)) {
								// bypass proxy for that hostname
								return new HttpRoute(host);
							}
						}
					}
					return super.determineRoute(host, request, context);
				}
			};

			httpClientBuilder.setRoutePlanner(routePlanner);
		}

		return httpClientBuilder.setProxy(proxy);
	}

	@Override
	public byte[] get(final String urlString) throws DSSException {

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
	public DataAndUrl get(final List<String> urlStrings) throws DSSException {
		if (Utils.isCollectionEmpty(urlStrings)) {
			throw new DSSException("Cannot process the GET call. List of URLs is empty!");
		}

		final Map<String, Throwable> exceptions = new HashMap<String, Throwable>(); // store map of exception thrown for urls
		for (String urlString : urlStrings) {
			LOG.debug("Processing a GET call to URL [{}]...", urlString);
			try {
				final byte[] bytes = get(urlString);
				if (Utils.isArrayEmpty(bytes)) {
					LOG.debug("The retrieved content from URL [{}] is empty. Continue with other URLs...", urlString);
					continue;
				}
				return new DataAndUrl(bytes, urlString);
			} catch (Exception e) {
				LOG.warn("Cannot obtain data using '{}' : {}", urlString, e.getMessage());
				exceptions.put(urlString, e);
			}
		}
		throw new DSSDataLoaderMultipleException(exceptions);
	}

	/**
	 * This method is useful only with the cache handling implementation of the
	 * {@code DataLoader}.
	 *
	 * @param url
	 *            to access
	 * @param refresh
	 *            if true indicates that the cached data should be refreshed
	 * @return {@code byte} array of obtained data
	 * @throws DSSException in case of DataLoader error
	 */
	@Override
	public byte[] get(final String url, final boolean refresh) throws DSSException {
		return get(url);
	}

	/**
	 * This method retrieves data using LDAP protocol. - CRL from given LDAP
	 * url, e.g. ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
	 * - ex URL from AIA
	 * ldap://xadessrv.plugtests.net/CN=LevelBCAOK,OU=Plugtests_2015-2016,O=ETSI,C=FR?cACertificate;binary
	 *
	 * @param urlString
	 * @return byte array
	 * @throws DSSException in case of DataLoader error
	 */
	protected byte[] ldapGet(String urlString) throws DSSException {
		
		urlString = LdapURLUtils.encode(urlString);

		final Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
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
				throw new DSSException(String.format("Cannot download binaries from: [%s], no attributes with name: [%s] returned", urlString, attributeName));
			} else {
				final Attribute attribute = attributes.getAll().next();
				final byte[] ldapBytes = (byte[]) attribute.get();
				if (Utils.isArrayNotEmpty(ldapBytes)) {
					return ldapBytes;
				}
				throw new DSSException(String.format("The retrieved ldap content from url [%s] is empty", urlString));
			}
		} catch (DSSException e) {
			throw e;
		} catch (Exception e) {
			throw new DSSExternalResourceException(String.format("Cannot get data from URL [%s]. Reason : [%s]", urlString, e.getMessage()), e);
		}
	}

	/**
	 * This method retrieves data using FTP protocol .
	 *
	 * @param urlString {@link String} url to retrieve data from
	 * @return byte array
	 * @throws DSSException in case of file download error
	 */
	protected byte[] ftpGet(final String urlString) throws DSSException {
		final URL url = getURL(urlString);
		try (InputStream inputStream = url.openStream()) {
			return DSSUtils.toByteArray(inputStream);
		} catch (IOException e) {
			throw new DSSExternalResourceException(String.format("Unable to retrieve file from URL %s. Reason : [%s]", urlString, e.getMessage()), e);
		}
	}

	protected byte[] fileGet(final String urlString) throws DSSException {
		return ftpGet(urlString);
	}

	private URL getURL(String urlString) {
		try {
			return new URL(urlString);
		} catch (MalformedURLException e) {
			throw new DSSException("Unable to create URL instance", e);
		}
	}

	/**
	 * This method retrieves data using HTTP or HTTPS protocol and 'get' method.
	 *
	 * @param url
	 *            to access
	 * @return {@code byte} array of obtained data or null
	 */
	protected byte[] httpGet(final String url) throws DSSException {

		HttpGet httpRequest = null;
		CloseableHttpResponse httpResponse = null;
		CloseableHttpClient client = null;
		try {

			final URI uri = new URI(url.trim());
			httpRequest = new HttpGet(uri);
			if (contentType != null) {
				httpRequest.setHeader(CONTENT_TYPE, contentType);
			}

			client = getHttpClient(url);
			httpResponse = getHttpResponse(client, httpRequest);

			return readHttpResponse(httpResponse);

		} catch (URISyntaxException | IOException e) {
			throw new DSSExternalResourceException(String.format("Unable to process GET call for url [%s]. Reason : [%s]", url, DSSUtils.getExceptionMessage(e)), e);
		} finally {
			try {
				if (httpRequest != null) {
					httpRequest.releaseConnection();
				}
				if (httpResponse != null) {
					EntityUtils.consumeQuietly(httpResponse.getEntity());
					Utils.closeQuietly(httpResponse);
				}
			} finally {
				Utils.closeQuietly(client);
			}
		}
	}

	@Override
	public byte[] post(final String url, final byte[] content) {

		LOG.debug("Fetching data via POST from url {}", url);

		HttpPost httpRequest = null;
		CloseableHttpResponse httpResponse = null;
		CloseableHttpClient client = null;
		try {
			final URI uri = URI.create(url.trim());
			httpRequest = new HttpPost(uri);

			// The length for the InputStreamEntity is needed, because some receivers (on the other side) need this
			// information.
			// To determine the length, we cannot read the content-stream up to the end and re-use it afterwards.
			// This is because, it may not be possible to reset the stream (= go to position 0).
			// So, the solution is to cache temporarily the complete content data (as we do not expect much here) in a
			// byte-array.
			final ByteArrayInputStream bis = new ByteArrayInputStream(content);

			final HttpEntity httpEntity = new InputStreamEntity(bis, content.length);
			final HttpEntity requestEntity = new BufferedHttpEntity(httpEntity);
			httpRequest.setEntity(requestEntity);
			if (contentType != null) {
				httpRequest.setHeader(CONTENT_TYPE, contentType);
			}

			client = getHttpClient(url);
			httpResponse = getHttpResponse(client, httpRequest);

			return readHttpResponse(httpResponse);
		} catch (IOException e) {
			throw new DSSExternalResourceException(String.format("Unable to process POST call for url [%s]. Reason : [%s]", url, e.getMessage()) , e);
		} finally {
			try {
				if (httpRequest != null) {
					httpRequest.releaseConnection();
				}
				if (httpResponse != null) {
					EntityUtils.consumeQuietly(httpResponse.getEntity());
					Utils.closeQuietly(httpResponse);
				}
			} finally {
				Utils.closeQuietly(client);
			}
		}
	}

	protected CloseableHttpResponse getHttpResponse(final CloseableHttpClient client, final HttpUriRequest httpRequest) throws IOException {
		final URI uri = httpRequest.getURI();
		final HttpHost targetHost = new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme());

		// Create AuthCache instance
		AuthCache authCache = new BasicAuthCache();
		// Generate BASIC scheme object and add it to the local
		// auth cache
		BasicScheme basicAuth = new BasicScheme();
		authCache.put(targetHost, basicAuth);

		// Add AuthCache to the execution context
		HttpClientContext localContext = HttpClientContext.create();
		localContext.setAuthCache(authCache);

		return client.execute(targetHost, httpRequest, localContext);
	}

	protected byte[] readHttpResponse(final CloseableHttpResponse httpResponse) throws IOException {
		final StatusLine statusLine = httpResponse.getStatusLine();
		final int statusCode = statusLine.getStatusCode();
		final String reasonPhrase = statusLine.getReasonPhrase();

		if (!acceptedHttpStatus.contains(statusCode)) {
			String reason = Utils.isStringNotEmpty(reasonPhrase) ? " / reason : " + reasonPhrase : "";
			throw new IOException("Not acceptable HTTP Status (HTTP status code : " + statusCode + reason + ")");
		}

		final HttpEntity responseEntity = httpResponse.getEntity();
		if (responseEntity == null) {
			throw new IOException("No message entity for this response");
		}

		return getContent(responseEntity);
	}

	protected byte[] getContent(final HttpEntity responseEntity) throws IOException {
		try (InputStream content = responseEntity.getContent()) {
			return DSSUtils.toByteArray(content);
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
	 * @param timeoutConnection
	 *            the value (millis)
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
	 * @param timeoutSocket
	 *            the value (millis)
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
	 * @param connectionsMaxTotal
	 *            maximum number of connections
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
	 * @param connectionsMaxPerRoute
	 *            maximum number of connections per one route
	 */
	public void setConnectionsMaxPerRoute(int connectionsMaxPerRoute) {
		this.connectionsMaxPerRoute = connectionsMaxPerRoute;
	}

	/**
	 * Used when the {@code HttpClient} is created.
	 *
	 * @return true if http redirects are allowed
	 */
	public boolean isRedirectsEnabled() {
		return redirectsEnabled;
	}

	/**
	 * Used when the {@code HttpClient} is created.
	 *
	 * @param redirectsEnabled
	 *            true if http redirects are allowed
	 */
	public void setRedirectsEnabled(boolean redirectsEnabled) {
		this.redirectsEnabled = redirectsEnabled;
	}

	/**
	 * @return the contentType
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * This allows to set the content type. Example: Content-Type
	 * "application/ocsp-request"
	 *
	 * @param contentType
	 */
	@Override
	public void setContentType(final String contentType) {
		this.contentType = contentType;
	}

	public List<Integer> getAcceptedHttpStatus() {
		return acceptedHttpStatus;
	}

	/**
	 * This allows to set a list of accepted http status. Example: 200 (OK)
	 *
	 * @param acceptedHttpStatus
	 *            a list of integer which correspond to the http status code
	 */
	public void setAcceptedHttpStatus(List<Integer> acceptedHttpStatus) {
		this.acceptedHttpStatus = acceptedHttpStatus;
	}

	/**
	 * @return associated {@code ProxyConfig}
	 */
	public ProxyConfig getProxyConfig() {
		return proxyConfig;
	}

	/**
	 * @param proxyConfig
	 *            the proxyConfig to set
	 */
	public void setProxyConfig(final ProxyConfig proxyConfig) {
		this.proxyConfig = proxyConfig;
	}

	/**
	 * This method sets the SSL protocol to be used ('TLSv1.2' by default)
	 * 
	 * @param sslProtocol
	 *                    the ssl protocol to be used
	 */
	public void setSslProtocol(String sslProtocol) {
		this.sslProtocol = sslProtocol;
	}

	public void setSslKeystorePath(String sslKeystorePath) {
		this.sslKeystorePath = sslKeystorePath;
	}

	public void setKeyStoreAsTrustMaterial(boolean loadKeyStoreAsTrustMaterial) {
		this.loadKeyStoreAsTrustMaterial = loadKeyStoreAsTrustMaterial;
	}

	public void setSslKeystoreType(String sslKeystoreType) {
		this.sslKeystoreType = sslKeystoreType;
	}

	public void setSslKeystorePassword(String sslKeystorePassword) {
		this.sslKeystorePassword = sslKeystorePassword;
	}

	public void setSslTruststorePath(final String sslTruststorePath) {
		this.sslTruststorePath = sslTruststorePath;
	}

	public void setSslTruststorePassword(final String sslTruststorePassword) {
		this.sslTruststorePassword = sslTruststorePassword;
	}

	public void setSslTruststoreType(String sslTruststoreType) {
		this.sslTruststoreType = sslTruststoreType;
	}

	/**
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
	 * @return this for fluent addAuthentication
	 */
	public CommonsDataLoader addAuthentication(final String host, final int port, final String scheme, final String login, final String password) {

		final HttpHost httpHost = new HttpHost(host, port, scheme);
		final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(login, password);
		authenticationMap.put(httpHost, credentials);

		return this;
	}

	/**
	 * This method allows to propagate the authentication information from the
	 * current object.
	 *
	 * @param commonsDataLoader
	 *            {@code CommonsDataLoader} to be initialized with
	 *            authentication information
	 */
	public void propagateAuthentication(final CommonsDataLoader commonsDataLoader) {

		for (final Map.Entry<HttpHost, UsernamePasswordCredentials> credentialsEntry : authenticationMap.entrySet()) {

			final HttpHost httpHost = credentialsEntry.getKey();
			final UsernamePasswordCredentials credentials = credentialsEntry.getValue();
			commonsDataLoader.addAuthentication(httpHost.getHostName(), httpHost.getPort(), httpHost.getSchemeName(), credentials.getUserName(),
					credentials.getPassword());
		}
	}

	public void setRetryHandler(final HttpRequestRetryHandler retryHandler) {
		this.retryHandler = retryHandler;
	}

	public void setServiceUnavailableRetryStrategy(final ServiceUnavailableRetryStrategy serviceUnavailableRetryStrategy) {
		this.serviceUnavailableRetryStrategy = serviceUnavailableRetryStrategy;
	}

	public String[] getSupportedSSLProtocols() {
		return supportedSSLProtocols;
	}

	public void setSupportedSSLProtocols(String[] supportedSSLProtocols) {
		this.supportedSSLProtocols = supportedSSLProtocols;
	}

	public String[] getSupportedSSLCipherSuites() {
		return supportedSSLCipherSuites;
	}

	public void setSupportedSSLCipherSuites(String[] supportedSSLCipherSuites) {
		this.supportedSSLCipherSuites = supportedSSLCipherSuites;
	}

	public HostnameVerifier getHostnameVerifier() {
		return hostnameVerifier;
	}

	public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
		this.hostnameVerifier = hostnameVerifier;
	}

	public TrustStrategy getTrustStrategy() {
		return trustStrategy;
	}

	public void setTrustStrategy(TrustStrategy trustStrategy) {
		this.trustStrategy = trustStrategy;
	}

}
