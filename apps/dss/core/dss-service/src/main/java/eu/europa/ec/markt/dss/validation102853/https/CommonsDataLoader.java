/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.https;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSCannotFetchDataException;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.manager.ProxyPreferenceManager;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.Protocol;

/**
 * Implementation of DataLoader for any protocol.<p/>
 * HTTP & HTTPS: using HttpClient which is more flexible for HTTPS without having to add the certificate to the JVM TrustStore. It takes into account a proxy management through
 * {@code ProxyPreferenceManager}. The authentication is also supported.<p/>
 *
 * @version $Revision$ - $Date$
 */
public class CommonsDataLoader implements DataLoader {

	private static final Logger LOG = LoggerFactory.getLogger(CommonsDataLoader.class);

	public static final int TIMEOUT_CONNECTION = 6000;

	public static final int TIMEOUT_SOCKET = 6000;

	public static final String CONTENT_TYPE = "Content-Type";

	protected String contentType;

	// TODO: (Bob: 2014 Jan 28) It should be taken into account: Content-Transfer-Encoding if it is not the default value.
	// TODO: (Bob: 2014 Jan 28) It is extracted from: https://joinup.ec.europa.eu/software/sd-dss/issue/dss-41-tsa-service-basic-auth
	// tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");

	private ProxyPreferenceManager proxyPreferenceManager;

	private int timeoutConnection = TIMEOUT_CONNECTION;
	private int timeoutSocket = TIMEOUT_SOCKET;

	private final Map<HttpHost, UsernamePasswordCredentials> authenticationMap = new HashMap<HttpHost, UsernamePasswordCredentials>();

	private HttpClient httpClient;

	/**
	 * The default constructor for CommonsDataLoader.
	 */
	public CommonsDataLoader() {
		this(null);
	}

	/**
	 * The  constructor for CommonsDataLoader with defined content-type.
	 *
	 * @param contentType The content type of each request
	 */
	public CommonsDataLoader(final String contentType) {
		this.contentType = contentType;
	}

	private HttpClientConnectionManager getConnectionManager() throws DSSException {

		LOG.debug("HTTPS TrustStore undefined, using default");
		RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder = RegistryBuilder.create();
		socketFactoryRegistryBuilder = setConnectionManagerSchemeHttp(socketFactoryRegistryBuilder);
		socketFactoryRegistryBuilder = setConnectionManagerSchemeHttps(socketFactoryRegistryBuilder);

		final HttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistryBuilder.build());
		return connectionManager;
	}

	private RegistryBuilder<ConnectionSocketFactory> setConnectionManagerSchemeHttp(RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder) {
		return socketFactoryRegistryBuilder.register("http", PlainConnectionSocketFactory.getSocketFactory());
	}

	private RegistryBuilder<ConnectionSocketFactory> setConnectionManagerSchemeHttps(RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder) throws DSSException {

		try {
			// TODO: (Bob: 2013 Dec 03) To be replaced: SSLSocketFactory deprecated!!!
			SSLSocketFactory sslSocketFactory = new SSLSocketFactory(new OptimistTrustStrategy(), new OptimistX509HostnameVerifier());
			return socketFactoryRegistryBuilder.register("https", sslSocketFactory);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	protected synchronized HttpClient getHttpClient(final String url) throws DSSException {

		if (httpClient != null) {

			return httpClient;
		} else {

			HttpClientBuilder httpClientBuilder = HttpClients.custom();

			httpClientBuilder = configCredentials(httpClientBuilder, url);

			final RequestConfig requestConfig = RequestConfig.custom().setSocketTimeout(timeoutSocket).setConnectionRequestTimeout(timeoutConnection).build();
			httpClientBuilder = httpClientBuilder.setDefaultRequestConfig(requestConfig);
			httpClientBuilder.setConnectionManager(getConnectionManager());

			httpClient = httpClientBuilder.build();
			return httpClient;
		}
	}

	/**
	 * Define the Credentials
	 *
	 * @param httpClientBuilder
	 * @param url
	 * @return
	 * @throws java.net.MalformedURLException
	 */
	private HttpClientBuilder configCredentials(HttpClientBuilder httpClientBuilder, final String url) throws DSSException {

		final CredentialsProvider credsProvider = new BasicCredentialsProvider();
		for (final Map.Entry<HttpHost, UsernamePasswordCredentials> entry : authenticationMap.entrySet()) {

			final HttpHost httpHost = entry.getKey();
			final UsernamePasswordCredentials usernamePasswordCredentials = entry.getValue();
			credsProvider.setCredentials(new AuthScope(httpHost.getHostName(), httpHost.getPort()), usernamePasswordCredentials);
		}
		httpClientBuilder = httpClientBuilder.setDefaultCredentialsProvider(credsProvider);
		httpClientBuilder = configureProxy(httpClientBuilder, credsProvider, url);
		return httpClientBuilder;
	}

	/**
	 * Configure the proxy with the required credential if needed
	 *
	 * @param httpClientBuilder
	 * @param credsProvider
	 * @param url
	 * @return
	 * @throws java.net.MalformedURLException
	 */
	private HttpClientBuilder configureProxy(HttpClientBuilder httpClientBuilder, CredentialsProvider credsProvider, String url) throws DSSException {

		try {

			if (proxyPreferenceManager == null) {
				return httpClientBuilder;
			}
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

			if (proxyHTTPS) {
				LOG.debug("Use proxy https parameters");
				final Long port = proxyPreferenceManager.getHttpsPort();
				proxyPort = port != null ? port.intValue() : 0;
				proxyHost = proxyPreferenceManager.getHttpsHost();
				proxyUser = proxyPreferenceManager.getHttpsUser();
				proxyPassword = proxyPreferenceManager.getHttpsPassword();
			} else // noinspection ConstantConditions
				if (proxyHTTP) {
					LOG.debug("Use proxy http parameters");
					final Long port = proxyPreferenceManager.getHttpPort();
					proxyPort = port != null ? port.intValue() : 0;
					proxyHost = proxyPreferenceManager.getHttpHost();
					proxyUser = proxyPreferenceManager.getHttpUser();
					proxyPassword = proxyPreferenceManager.getHttpPassword();

				}

			if (DSSUtils.isNotEmpty(proxyUser) && DSSUtils.isNotEmpty(proxyPassword)) {
				LOG.debug("proxy user: " + proxyUser + ":" + proxyPassword);
				AuthScope proxyAuth = new AuthScope(proxyHost, proxyPort);
				UsernamePasswordCredentials proxyCredentials = new UsernamePasswordCredentials(proxyUser, proxyPassword);
				credsProvider.setCredentials(proxyAuth, proxyCredentials);
			}

			LOG.debug("proxy host/port: " + proxyHost + ":" + proxyPort);
			// TODO SSL peer shut down incorrectly when protocol is https
			HttpHost proxy = new HttpHost(proxyHost, proxyPort, Protocol.HTTP.getName());
			return httpClientBuilder.setProxy(proxy);
		} catch (MalformedURLException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public byte[] get(final String urlString) throws DSSCannotFetchDataException {

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

	private byte[] fileGet(String urlString) {
		try {
			return DSSUtils.toByteArray(new URL(urlString).openStream());
		} catch (IOException e) {
			LOG.warn(e.toString(), e);
		}
		return null;
	}

	//    /**
	//     * Obtains a CRL from a specified LDAP URL (Another method)
	//     *
	//     * @param ldapURL The LDAP URL String
	//     * @return A CRL obtained from this LDAP URL if successful, otherwise NULL (if no CRL was resent) or an exception will be thrown.
	//     * @throws DSSException
	//     */
	//    public static byte[] ldapGet2(final String ldapURL) throws DSSException {
	//
	//        try {
	//
	//            //final String ldapUrlStr = URLDecoder.decode(ldapURL, "UTF-8");
	//            final LdapUrl ldapUrl = new LdapUrl(ldapURL);
	//            final int port = ldapUrl.getPort() > 0 ? ldapUrl.getPort() : 389;
	//            final LdapConnection con = new LdapNetworkConnection(ldapUrl.getHost(), port);
	//            con.connect();
	//            final Entry entry = con.lookup(ldapUrl.getDn(), ldapUrl.getAttributes().toArray(new String[ldapUrl.getAttributes().size()]));
	//            final Collection<Attribute> attributes = entry.getAttributes();
	//            byte[] bytes = null;
	//            for (Attribute attr : attributes) {
	//
	//                bytes = attr.getBytes();
	//                break;
	//            }
	//            con.close();
	//            return bytes;
	//        } catch (Exception e) {
	//
	//            LOG.warn(e.toString(), e);
	//        }
	//        return null;
	//    }
	//

	/**
	 * This method retrieves data using LDAP protocol.
	 * - CRL from given LDAP url, e.g. ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
	 *
	 * @param urlString
	 * @return
	 */
	private byte[] ldapGet(final String urlString) {

		final Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, urlString);
		try {

			final DirContext ctx = new InitialDirContext(env);
			final Attributes attributes = ctx.getAttributes("");
			final javax.naming.directory.Attribute attribute = attributes.get("certificateRevocationList;binary");
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

		InputStream inputStream = null;
		try {

			final URL url = new URL(urlString);
			inputStream = url.openStream();
			return DSSUtils.toByteArray(inputStream);
		} catch (Exception e) {

			LOG.warn(e.getMessage());
		} finally {
			DSSUtils.closeQuietly(inputStream);
		}
		return null;
	}

	/**
	 * This method retrieves data using HTTP or HTTPS protocol and 'get' method.
	 *
	 * @param url
	 * @return
	 */
	protected byte[] httpGet(String url) {

		HttpGet httpRequest = null;
		HttpResponse httpResponse = null;
		try {

			final URI uri = URI.create(url.trim());
			httpRequest = new HttpGet(uri);
			if (contentType != null) {
				httpRequest.setHeader(CONTENT_TYPE, contentType);
			}

			httpResponse = getHttpResponse(httpRequest, url);

			final byte[] returnedBytes = readHttpResponse(url, httpResponse);
			return returnedBytes;
		} finally {
			if (httpRequest != null) {
				httpRequest.releaseConnection();
			}
			if (httpResponse != null) {
				EntityUtils.consumeQuietly(httpResponse.getEntity());
			}
		}
	}

	@Override
	public byte[] post(final String url, final byte[] content) throws DSSException {

		LOG.debug("Fetching data via POST from url " + url);

		HttpPost httpRequest = null;
		HttpResponse httpResponse = null;

		try {
			final URI uri = URI.create(url.trim());
			httpRequest = new HttpPost(uri);

			// The length for the InputStreamEntity is needed, because some receivers (on the other side) need this information.
			// To determine the length, we cannot read the content-stream up to the end and re-use it afterwards.
			// This is because, it may not be possible to reset the stream (= go to position 0).
			// So, the solution is to cache temporarily the complete content data (as we do not expect much here) in a byte-array.
			final ByteArrayInputStream bis = new ByteArrayInputStream(content);

			final HttpEntity requestEntity = new InputStreamEntity(bis, content.length);
			httpRequest.setEntity(requestEntity);
			if (contentType != null) {
				httpRequest.setHeader(CONTENT_TYPE, contentType);
			}

			httpResponse = getHttpResponse(httpRequest, url);

			final byte[] returnedBytes = readHttpResponse(url, httpResponse);
			return returnedBytes;
		} finally {
			if (httpRequest != null) {
				httpRequest.releaseConnection();
			}
			if (httpResponse != null) {
				EntityUtils.consumeQuietly(httpResponse.getEntity());
			}
		}
	}

	protected HttpResponse getHttpResponse(final HttpUriRequest httpRequest, final String url) throws DSSException {

		final HttpClient client = getHttpClient(url);

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
		final boolean statusOk = statusCode == HttpStatus.SC_OK;
		LOG.debug("status code is " + statusCode + " - " + (statusOk ? "OK" : "NOK"));
		if (!statusOk) {

			LOG.warn("No content available via url: " + url + " - will use nothing: " + url);
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}

		final HttpEntity responseEntity = httpResponse.getEntity();
		if (responseEntity == null) {
			LOG.warn("No message entity for this response - will use nothing: " + url);
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}

		final byte[] content = getContent(responseEntity);
		return content;
	}

	protected byte[] getContent(final HttpEntity responseEntity) throws DSSException {

		try {

			final InputStream content = responseEntity.getContent();
			final byte[] bytes = DSSUtils.toByteArray(content);
			content.close();
			return bytes;
		} catch (IOException e) {
			throw new DSSException(e);
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
		httpClient = null;
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
		httpClient = null;
		this.timeoutSocket = timeoutSocket;
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
	 * @param proxyPreferenceManager the proxyPreferenceManager to set
	 */
	public void setProxyPreferenceManager(final ProxyPreferenceManager proxyPreferenceManager) {
		httpClient = null;
		this.proxyPreferenceManager = proxyPreferenceManager;
	}

	/**
	 * @param host
	 * @param port
	 * @param scheme
	 * @param login
	 * @param password
	 * @return this for fluent addAuthentication
	 */
	public CommonsDataLoader addAuthentication(final String host, final int port, final String scheme, final String login, final String password) {

		final HttpHost httpHost = new HttpHost(host, port, scheme);
		final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(login, password);
		authenticationMap.put(httpHost, credentials);
		httpClient = null;
		return this;
	}
}
