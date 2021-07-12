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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.exception.DSSDataLoaderMultipleException;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
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
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
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
	private static final int TIMEOUT_CONNECTION = 60000;

	/** The default socket timeout (1 minute) */
	private static final int TIMEOUT_SOCKET = 60000;

	/** The default value of maximum connections in time (20) */
	private static final int CONNECTIONS_MAX_TOTAL = 20;

	/** The default value of maximum connections per route (2) */
	private static final int CONNECTIONS_MAX_PER_ROUTE = 2;

	/** The content-type string */
	private static final String CONTENT_TYPE = "Content-Type";

	/** The default SSL protocol */
	private static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";

	/** The list of accepted statuses for a successful connection */
	private static final List<Integer> ACCEPTED_HTTP_STATUS = Arrays.asList(HttpStatus.SC_OK);

	/** The content type value */
	protected String contentType;

	/** The proxy configuration */
	private ProxyConfig proxyConfig;

	/** The timeout connection */
	private int timeoutConnection = TIMEOUT_CONNECTION;

	/** The connection request timeout */
	private int timeoutConnectionRequest = TIMEOUT_CONNECTION;

	/** The timeout socket */
	private int timeoutSocket = TIMEOUT_SOCKET;

	/** Maximum connections number in time */
	private int connectionsMaxTotal = CONNECTIONS_MAX_TOTAL;

	/** Maximum connections number per route */
	private int connectionsMaxPerRoute = CONNECTIONS_MAX_PER_ROUTE;

	/** Defines if the redirection is enabled */
	private boolean redirectsEnabled = true;

	/** Defines if the default system network properties shall be used */
	private boolean useSystemProperties = false;

	/** Defines the accepted HTTP statuses */
	private List<Integer> acceptedHttpStatus = ACCEPTED_HTTP_STATUS;

	/** Contains rules credentials for authentication to different resources */
	private Map<HostConnection, UserCredentials> authenticationMap;

	/**
	 * Used SSL protocol
	 */
	private String sslProtocol = DEFAULT_SSL_PROTOCOL;

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
	private String sslKeystorePassword = Utils.EMPTY_STRING;

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
	private String sslTruststorePassword = Utils.EMPTY_STRING;

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
	private transient HostnameVerifier hostnameVerifier = SSLConnectionSocketFactory.getDefaultHostnameVerifier();

	/**
	 * The connection retry handler
	 */
	private transient HttpRequestRetryHandler retryHandler;

	/**
	 * The strategy to retry for unavailable services
	 */
	private transient ServiceUnavailableRetryStrategy serviceUnavailableRetryStrategy;

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
			
			TrustStrategy trustStrategy = getTrustStrategy();
			if (trustStrategy != null) {
				LOG.debug("Set the TrustStrategy");
				sslContextBuilder.loadTrustMaterial(null, trustStrategy);
			}

			final KeyStore sslTrustStore = getSSLTrustStore();
			if (sslTrustStore != null) {
				LOG.debug("Set the SSL trust store as trust materials");
				sslContextBuilder.loadTrustMaterial(sslTrustStore, trustStrategy);
			}

			final KeyStore sslKeystore = getSSLKeyStore();
			if (sslKeystore != null) {
				LOG.debug("Set the SSL keystore as key materials");
				final char[] password = sslKeystorePassword != null ? sslKeystorePassword.toCharArray() : null;
				sslContextBuilder.loadKeyMaterial(sslKeystore, password);
				if (loadKeyStoreAsTrustMaterial) {
					LOG.debug("Set the SSL keystore as trust materials");
					sslContextBuilder.loadTrustMaterial(sslKeystore, trustStrategy);
				}
			}

			SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContextBuilder.build(), getSupportedSSLProtocols(),
					getSupportedSSLCipherSuites(), getHostnameVerifier());
			return socketFactoryRegistryBuilder.register("https", sslConnectionSocketFactory);
		} catch (final Exception e) {
			throw new IllegalArgumentException("Unable to configure the SSLContext/SSLConnectionSocketFactory", e);
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

	private KeyStore loadKeyStore(DSSDocument store, String type, String passwordStr) throws IOException, GeneralSecurityException {
		if (store != null) {
			try (InputStream is = store.openStream()) {
				KeyStore ks = KeyStore.getInstance(type);
				final char[] password = passwordStr != null ? passwordStr.toCharArray() : null;
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

		final RequestConfig.Builder custom = RequestConfig.custom();
		custom.setSocketTimeout(timeoutSocket);
		custom.setConnectTimeout(timeoutConnection);
		custom.setConnectionRequestTimeout(timeoutConnectionRequest);
		custom.setRedirectsEnabled(redirectsEnabled);
		custom.setCookieSpec(CookieSpecs.STANDARD); // to allow interoperability with RFC 6265 cookies

		final RequestConfig requestConfig = custom.build();
		httpClientBuilder = httpClientBuilder.setDefaultRequestConfig(requestConfig);
		httpClientBuilder.setConnectionManager(getConnectionManager());

		httpClientBuilder.setRetryHandler(retryHandler);
		httpClientBuilder.setServiceUnavailableRetryStrategy(serviceUnavailableRetryStrategy);
		
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
	 * Define the Credentials
	 *
	 * @param httpClientBuilder {@link HttpClientBuilder}
	 * @param url {@link String}
	 * @return {@link HttpClientBuilder}
	 */
	private HttpClientBuilder configCredentials(HttpClientBuilder httpClientBuilder, final String url) {

		final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		for (final Map.Entry<HostConnection, UserCredentials> entry : getAuthenticationMap().entrySet()) {
			final HostConnection hostConnection = entry.getKey();
			final UserCredentials userCredentials = entry.getValue();
			final AuthScope authscope = new AuthScope(hostConnection.getHost(), hostConnection.getPort(),
					hostConnection.getRealm(), hostConnection.getScheme());
			final UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(
					userCredentials.getUsername(), userCredentials.getPassword());
			credentialsProvider.setCredentials(authscope, usernamePasswordCredentials);
		}
		httpClientBuilder = httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
		httpClientBuilder = configureProxy(httpClientBuilder, credentialsProvider, url);
		return httpClientBuilder;
	}

	/**
	 * Configure the proxy with the required credential if needed
	 *
	 * @param httpClientBuilder {@link HttpClientBuilder}
	 * @param credentialsProvider {@link CredentialsProvider}
	 * @param url {@link String}
	 * @return {@link HttpClientBuilder}
	 */
	private HttpClientBuilder configureProxy(HttpClientBuilder httpClientBuilder,
											 CredentialsProvider credentialsProvider, String url) {
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
		
		urlString = LdapURLUtils.encode(urlString);

		final Hashtable<String, String> env = new Hashtable<>();
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
			return new URL(urlString);
		} catch (MalformedURLException e) {
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
		CloseableHttpResponse httpResponse = null;
		CloseableHttpClient client = null;
		
		try {
			httpRequest = getHttpRequest(url);
			client = getHttpClient(url);
			httpResponse = getHttpResponse(client, httpRequest);

			return readHttpResponse(httpResponse);

		} catch (URISyntaxException | IOException e) {
			throw new DSSExternalResourceException(String.format("Unable to process GET call for url [%s]. Reason : [%s]", url, DSSUtils.getExceptionMessage(e)), e);
		
		} finally {
			closeQuietly(httpRequest, httpResponse, client);
		
		}
	}

	/**
	 * Closes all the parameters quietly
	 *
	 * @param httpRequest {@link HttpRequestBase}
	 * @param httpResponse {@link CloseableHttpResponse}
	 * @param client {@link CloseableHttpClient}
	 */
	protected void closeQuietly(HttpRequestBase httpRequest, CloseableHttpResponse httpResponse,
								CloseableHttpClient client) {
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

	@Override
	public byte[] post(final String url, final byte[] content) {

		LOG.debug("Fetching data via POST from url {}", url);

		HttpPost httpRequest = null;
		CloseableHttpResponse httpResponse = null;
		CloseableHttpClient client = null;
		try {
			final URI uri = URI.create(Utils.trim(url));
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
			closeQuietly(httpRequest, httpResponse, client);
		
		}
	}

	/**
	 * Processes {@code httpRequest} and returns the {@code CloseableHttpResponse}
	 *
	 * @param client {@link CloseableHttpClient}
	 * @param httpRequest {@link HttpUriRequest}
	 * @return {@link CloseableHttpResponse}
	 * @throws IOException if an exception occurs
	 */
	protected CloseableHttpResponse getHttpResponse(final CloseableHttpClient client,
													final HttpUriRequest httpRequest) throws IOException {
		final HttpHost targetHost = getHttpHost(httpRequest);
		final HttpContext localContext = getHttpContext(targetHost);
		return client.execute(targetHost, httpRequest, localContext);
	}

	/**
	 * Gets the {@code HttpHost}
	 *
	 * @param httpRequest {@link HttpUriRequest}
	 * @return {@link HttpHost}
	 */
	protected HttpHost getHttpHost(final HttpUriRequest httpRequest) {
		final URI uri = httpRequest.getURI();
		return new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme());
	}

	/**
	 * Gets the {@code HttpContext}
	 *
	 * @param targetHost {@link HttpHost}
	 * @return {@link HttpContext}
	 */
	protected HttpContext getHttpContext(final HttpHost targetHost) {
		// Create AuthCache instance
		AuthCache authCache = new BasicAuthCache();
		// Generate BASIC scheme object and add it to the local
		// auth cache
		BasicScheme basicAuth = new BasicScheme();
		authCache.put(targetHost, basicAuth);

		// Add AuthCache to the execution context
		HttpClientContext localContext = HttpClientContext.create();
		localContext.setAuthCache(authCache);
		return localContext;
	}

	/**
	 * Reads the HTTP response
	 *
	 * @param httpResponse {@link CloseableHttpResponse}
	 * @return the response's content
	 * @throws IOException if an exception occurs
	 */
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

	/**
	 * Gets content of the response
	 *
	 * @param responseEntity {@link HttpEntity}
	 * @return byte array
	 * @throws IOException if an exception occurs
	 */
	protected byte[] getContent(final HttpEntity responseEntity) throws IOException {
		try (InputStream content = responseEntity.getContent()) {
			return DSSUtils.toByteArray(content);
		}
	}

	/**
	 * Gets the connection timeout.
	 *
	 * @return the value (millis)
	 */
	public int getTimeoutConnection() {
		return timeoutConnection;
	}

	/**
	 * Sets the connection timeout.
	 *
	 * @param timeoutConnection
	 *            the value (millis)
	 */
	public void setTimeoutConnection(final int timeoutConnection) {
		this.timeoutConnection = timeoutConnection;
	}

	/**
	 * Gets the connection request timeout.
	 *
	 * @return the value (millis)
	 */
	public int getTimeoutConnectionRequest() {
		return timeoutConnectionRequest;
	}

	/**
	 * Sets the connection request timeout.
	 *
	 * @param timeoutConnectionRequest
	 *            the value (millis)
	 */
	public void setTimeoutConnectionRequest(int timeoutConnectionRequest) {
		this.timeoutConnectionRequest = timeoutConnectionRequest;
	}

	/**
	 * Gets the socket timeout.
	 *
	 * @return the value (millis)
	 */
	public int getTimeoutSocket() {
		return timeoutSocket;
	}

	/**
	 * Sets the socket timeout.
	 *
	 * @param timeoutSocket
	 *            the value (millis)
	 */
	public void setTimeoutSocket(final int timeoutSocket) {
		this.timeoutSocket = timeoutSocket;
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
	 * @return the contentType
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * This allows to set the content type. Example: Content-Type
	 * "application/ocsp-request"
	 *
	 * @param contentType {@link String}
	 */
	@Override
	public void setContentType(final String contentType) {
		this.contentType = contentType;
	}

	/**
	 * Returns a list of accepted HTTP status numbers
	 *
	 * @return a list of accepted HTTP status numbers
	 */
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
	 * Sets the KeyStore password
	 *
	 * @param sslKeystorePassword {@link String}
	 */
	public void setSslKeystorePassword(String sslKeystorePassword) {
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
	 * @param sslTruststorePassword {@link String}
	 */
	public void setSslTruststorePassword(final String sslTruststorePassword) {
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
	 * @return this for fluent addAuthentication
	 */
	public CommonsDataLoader addAuthentication(HostConnection hostConnection, UserCredentials userCredentials) {
		Map<HostConnection, UserCredentials> authenticationMap = getAuthenticationMap();
		authenticationMap.put(hostConnection, userCredentials);
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
	 * @return this for fluent addAuthentication
	 */
	public CommonsDataLoader addAuthentication(final String host, final int port, final String scheme,
											   final String login, final String password) {
		final HostConnection hostConnection = new HostConnection(host, port, scheme);
		final UserCredentials userCredentials = new UserCredentials(login, password);
		return addAuthentication(hostConnection, userCredentials);
	}

	/**
	 * This method allows to propagate the authentication information from the
	 * current object.
	 *
	 * Deprecated. Please use
	 * {@code
	 * 		currentDataLoader.setAuthenticationMap(oldDataLoader.getAuthenticationMap());
	 * }
	 *
	 * @param commonsDataLoader
	 *            {@code CommonsDataLoader} to be initialized with
	 *            authentication information
	 * @deprecated since v5.9
	 */
	@Deprecated
	public void propagateAuthentication(final CommonsDataLoader commonsDataLoader) {
		setAuthenticationMap(commonsDataLoader.getAuthenticationMap());
	}

	/**
	 * Sets a custom retry handler
	 *
	 * @param retryHandler {@link HttpRequestRetryHandler}
	 */
	public void setRetryHandler(final HttpRequestRetryHandler retryHandler) {
		this.retryHandler = retryHandler;
	}

	/**
	 * Sets custom {@code ServiceUnavailableRetryStrategy}
	 *
	 * @param serviceUnavailableRetryStrategy {@link ServiceUnavailableRetryStrategy}
	 */
	public void setServiceUnavailableRetryStrategy(final ServiceUnavailableRetryStrategy serviceUnavailableRetryStrategy) {
		this.serviceUnavailableRetryStrategy = serviceUnavailableRetryStrategy;
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

}
