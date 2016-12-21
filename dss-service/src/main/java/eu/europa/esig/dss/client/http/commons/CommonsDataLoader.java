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
package eu.europa.esig.dss.client.http.commons;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
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
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
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
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.Protocol;
import eu.europa.esig.dss.client.http.proxy.ProxyPreferenceManager;
import eu.europa.esig.dss.utils.Utils;

/**
 * Implementation of DataLoader for any protocol.
 * <p/>
 * HTTP & HTTPS: using HttpClient which is more flexible for HTTPS without
 * having to add the certificate to the JVM TrustStore. It takes into account a
 * proxy management through {@code ProxyPreferenceManager}. The authentication
 * is also supported.
 */
public class CommonsDataLoader implements DataLoader, DSSNotifier {

	private static final Logger LOG = LoggerFactory.getLogger(CommonsDataLoader.class);

	public static final int TIMEOUT_CONNECTION = 6000;

	public static final int TIMEOUT_SOCKET = 6000;

	public static final int CONNECTIONS_MAX_TOTAL = 20;

	public static final int CONNECTIONS_MAX_PER_ROUTE = 2;

	public static final String CONTENT_TYPE = "Content-Type";

	protected String contentType;

	// TODO: (Bob: 2014 Jan 28) It should be taken into account: Content-Transfer-Encoding if it is not the default
	// value.
	// TODO: (Bob: 2014 Jan 28) It is extracted from:
	// https://joinup.ec.europa.eu/software/sd-dss/issue/dss-41-tsa-service-basic-auth
	// tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");
	private ProxyPreferenceManager proxyPreferenceManager;

	private int timeoutConnection = TIMEOUT_CONNECTION;
	private int timeoutSocket = TIMEOUT_SOCKET;
	private int connectionsMaxTotal = CONNECTIONS_MAX_TOTAL;
	private int connectionsMaxPerRoute = CONNECTIONS_MAX_PER_ROUTE;
	private boolean redirectsEnabled = true;

	private final Map<HttpHost, UsernamePasswordCredentials> authenticationMap = new HashMap<HttpHost, UsernamePasswordCredentials>();

	private boolean updated;

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

	private HttpClientConnectionManager getConnectionManager() throws DSSException {

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

	private RegistryBuilder<ConnectionSocketFactory> setConnectionManagerSchemeHttps(
			final RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder) throws DSSException {
		FileInputStream fis = null;
		FileInputStream trustStoreIs = null;
		try {

			X509TrustManager trustManager = null;
			if (Utils.isStringEmpty(sslTruststorePath)) {
				trustManager = new AcceptAllTrustManager();
			} else {
				trustStoreIs = new FileInputStream(new File(sslTruststorePath));
				trustManager = new DefaultTrustManager(trustStoreIs, sslTruststoreType, sslTruststorePassword);
			}

			KeyManager[] keysManager = null;
			if (Utils.isStringEmpty(sslKeystorePath)) {
				LOG.debug("Use default SSL configuration");
				keysManager = new KeyManager[0];
			} else {
				LOG.debug("Use provided info for SSL");
				fis = new FileInputStream(new File(sslKeystorePath));
				DefaultKeyManager dkm = new DefaultKeyManager(fis, sslKeystoreType, sslKeystorePassword);
				keysManager = new KeyManager[] { dkm };
			}

			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(keysManager, new TrustManager[] { trustManager }, new SecureRandom());

			SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContext);
			return socketFactoryRegistryBuilder.register("https", sslConnectionSocketFactory);
		} catch (final Exception e) {
			throw new DSSException(e);
		} finally {
			Utils.closeQuietly(fis);
			Utils.closeQuietly(trustStoreIs);
		}
	}

	protected synchronized CloseableHttpClient getHttpClient(final String url) throws DSSException {

		if (LOG.isTraceEnabled() && updated) {
			LOG.trace(">>> Proxy preferences updated");
		}
		HttpClientBuilder httpClientBuilder = HttpClients.custom();

		httpClientBuilder = configCredentials(httpClientBuilder, url);

		final RequestConfig.Builder custom = RequestConfig.custom();
		custom.setSocketTimeout(timeoutSocket);
		custom.setConnectTimeout(timeoutConnection);
		custom.setRedirectsEnabled(redirectsEnabled);

		final RequestConfig requestConfig = custom.build();
		httpClientBuilder = httpClientBuilder.setDefaultRequestConfig(requestConfig);
		httpClientBuilder.setConnectionManager(getConnectionManager());

		CloseableHttpClient httpClient = httpClientBuilder.build();
		return httpClient;
	}

	/**
	 * Define the Credentials
	 *
	 * @param httpClientBuilder
	 * @param url
	 * @return
	 */
	private HttpClientBuilder configCredentials(HttpClientBuilder httpClientBuilder, final String url) throws DSSException {

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
	 * @return
	 */
	private HttpClientBuilder configureProxy(HttpClientBuilder httpClientBuilder, CredentialsProvider credentialsProvider, String url) throws DSSException {

		if (proxyPreferenceManager == null) {
			return httpClientBuilder;
		}
		try {

			final String protocol = new URL(url).getProtocol();
			final boolean proxyHTTPS = Protocol.isHttps(protocol) && proxyPreferenceManager.isHttpsEnabled();
			final boolean proxyHTTP = Protocol.isHttp(protocol) && proxyPreferenceManager.isHttpEnabled();

			if (!proxyHTTPS && !proxyHTTP) {
				return httpClientBuilder;
			}

			String proxyHost = null;
			int proxyPort = 0;
			String proxyUser = null;
			String proxyPassword = null;
			String proxyExcludedHosts = null;

			if (proxyHTTPS) {

				LOG.debug("Use proxy https parameters");
				final Long port = proxyPreferenceManager.getHttpsPort();
				proxyPort = port != null ? port.intValue() : 0;
				proxyHost = proxyPreferenceManager.getHttpsHost();
				proxyUser = proxyPreferenceManager.getHttpsUser();
				proxyPassword = proxyPreferenceManager.getHttpsPassword();
				proxyExcludedHosts = proxyPreferenceManager.getHttpsExcludedHosts();
			} else if (proxyHTTP) { // noinspection ConstantConditions

				LOG.debug("Use proxy http parameters");
				final Long port = proxyPreferenceManager.getHttpPort();
				proxyPort = port != null ? port.intValue() : 0;
				proxyHost = proxyPreferenceManager.getHttpHost();
				proxyUser = proxyPreferenceManager.getHttpUser();
				proxyPassword = proxyPreferenceManager.getHttpPassword();
				proxyExcludedHosts = proxyPreferenceManager.getHttpExcludedHosts();
			}
			if (Utils.isStringNotEmpty(proxyUser) && Utils.isStringNotEmpty(proxyPassword)) {

				AuthScope proxyAuth = new AuthScope(proxyHost, proxyPort);
				UsernamePasswordCredentials proxyCredentials = new UsernamePasswordCredentials(proxyUser, proxyPassword);
				credentialsProvider.setCredentials(proxyAuth, proxyCredentials);
			}

			LOG.debug("proxy host/port: " + proxyHost + ":" + proxyPort);
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

			final HttpClientBuilder httpClientBuilder1 = httpClientBuilder.setProxy(proxy);
			updated = false;
			return httpClientBuilder1;
		} catch (MalformedURLException e) {
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
	 * This method is useful only with the cache handling implementation of the
	 * {@code DataLoader}.
	 *
	 * @param url
	 *            to access
	 * @param refresh
	 *            if true indicates that the cached data should be refreshed
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
			LOG.warn("An IO error occured while reading url " + urlString, e);
		}
		return null;
	}

	/**
	 * This method retrieves data using LDAP protocol. - CRL from given LDAP
	 * url, e.g. ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
	 * - ex URL from AIA
	 * ldap://xadessrv.plugtests.net/CN=LevelBCAOK,OU=Plugtests_2015-2016,O=ETSI,C=FR?cACertificate;binary
	 *
	 * @param urlString
	 * @return
	 */
	protected byte[] ldapGet(final String urlString) {

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
			if (attributes == null || attributes.size() < 1) {
				LOG.warn("Cannot download CRL from: " + urlString + ", no attributes with name: " + attributeName + " returned");
			} else {
				final Attribute attribute = attributes.getAll().next();
				final byte[] ldapBytes = (byte[]) attribute.get();
				if (Utils.isArrayNotEmpty(ldapBytes)) {
					return ldapBytes;
				}
			}
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

		InputStream inputStream = null;
		try {

			final URL url = new URL(urlString);
			inputStream = url.openStream();
			return DSSUtils.toByteArray(inputStream);
		} catch (Exception e) {

			LOG.warn(e.getMessage());
		} finally {
			Utils.closeQuietly(inputStream);
		}
		return null;
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
		HttpResponse httpResponse = null;
		CloseableHttpClient client = null;
		try {

			final URI uri = new URI(url.trim());
			httpRequest = new HttpGet(uri);
			if (contentType != null) {
				httpRequest.setHeader(CONTENT_TYPE, contentType);
			}

			client = getHttpClient(url);
			httpResponse = getHttpResponse(client, httpRequest, url);

			final byte[] returnedBytes = readHttpResponse(url, httpResponse);
			return returnedBytes;

		} catch (URISyntaxException e) {
			throw new DSSException(e);

		} finally {

			try {
				if (httpRequest != null) {
					httpRequest.releaseConnection();
				}
				if (httpResponse != null) {
					EntityUtils.consumeQuietly(httpResponse.getEntity());
				}
			} finally {
				closeClient(client);
			}
		}
	}

	@Override
	public byte[] post(final String url, final byte[] content) throws DSSException {

		LOG.debug("Fetching data via POST from url " + url);

		HttpPost httpRequest = null;
		HttpResponse httpResponse = null;
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
			httpResponse = getHttpResponse(client, httpRequest, url);

			final byte[] returnedBytes = readHttpResponse(url, httpResponse);
			return returnedBytes;
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			try {
				if (httpRequest != null) {
					httpRequest.releaseConnection();
				}
				if (httpResponse != null) {
					EntityUtils.consumeQuietly(httpResponse.getEntity());
				}
			} finally {
				closeClient(client);
			}
		}
	}

	void closeClient(CloseableHttpClient httpClient) {
		if (httpClient != null) {
			try {
				httpClient.close();
			} catch (Exception ex) {
				LOG.warn("Cound not close client", ex);
			} finally {
				httpClient = null;
			}
		}
	}

	protected HttpResponse getHttpResponse(final CloseableHttpClient client, final HttpUriRequest httpRequest, final String url) throws DSSException {

		final String host = httpRequest.getURI().getHost();
		final int port = httpRequest.getURI().getPort();
		final String scheme = httpRequest.getURI().getScheme();
		final HttpHost targetHost = new HttpHost(host, port, scheme);

		// Create AuthCache instance
		AuthCache authCache = new BasicAuthCache();
		// Generate BASIC scheme object and add it to the local
		// auth cache
		BasicScheme basicAuth = new BasicScheme();
		authCache.put(targetHost, basicAuth);

		// Add AuthCache to the execution context
		HttpClientContext localContext = HttpClientContext.create();
		localContext.setAuthCache(authCache);

		try {
			final HttpResponse response = client.execute(targetHost, httpRequest, localContext);
			return response;
		} catch (IOException e) {
			throw new DSSException(e);
		}

	}

	protected byte[] readHttpResponse(final String url, final HttpResponse httpResponse) throws DSSException {

		final int statusCode = httpResponse.getStatusLine().getStatusCode();
		if (LOG.isDebugEnabled()) {
			LOG.debug(url + " status code is " + statusCode + " - " + (statusCode == HttpStatus.SC_OK ? "OK" : "NOK"));
		}

		if (statusCode != HttpStatus.SC_OK) {
			LOG.warn("No content available via url: " + url);
			return null;
		}

		final HttpEntity responseEntity = httpResponse.getEntity();
		if (responseEntity == null) {
			LOG.warn("No message entity for this response - will use nothing: " + url);
			return null;
		}

		final byte[] content = getContent(responseEntity);
		return content;
	}

	protected byte[] getContent(final HttpEntity responseEntity) throws DSSException {
		InputStream content = null;
		try {
			content = responseEntity.getContent();
			final byte[] bytes = DSSUtils.toByteArray(content);
			return bytes;
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			Utils.closeQuietly(content);
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

	/**
	 * @return associated {@code ProxyPreferenceManager}
	 */
	public ProxyPreferenceManager getProxyPreferenceManager() {
		return proxyPreferenceManager;
	}

	/**
	 * @param proxyPreferenceManager
	 *            the proxyPreferenceManager to set
	 */
	public void setProxyPreferenceManager(final ProxyPreferenceManager proxyPreferenceManager) {

		this.proxyPreferenceManager = proxyPreferenceManager;
		if (proxyPreferenceManager != null) {
			proxyPreferenceManager.addNotifier(this);
			if (LOG.isTraceEnabled()) {
				LOG.trace(">>> SET: " + proxyPreferenceManager);
			}
		}
	}

	public void setSslKeystorePath(String sslKeystorePath) {
		this.sslKeystorePath = sslKeystorePath;
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

	@Override
	public void update() {
		updated = true;
	}

}