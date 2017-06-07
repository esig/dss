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
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.AuthCache;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;

/**
 * Implementation of DataLoader using HttpClient to request a timestamp server.
 */
public class TimestampDataLoader extends CommonsDataLoader {

	private static final Logger LOG = LoggerFactory.getLogger(CommonsDataLoader.class);
	
	public static final String TIMESTAMP_QUERY_CONTENT_TYPE = "application/timestamp-query";

	public String[] supportedProtocols 		= new String[] {  "TLSv1", "TLSv1.2" };
	
	public String[] supportedCipherSuits 	= null;
	
	public HostnameVerifier customHostNameVerifier  = null; 
	/**
	 * The default constructor for CommonsDataLoader.
	 */
	public TimestampDataLoader() {
		super(TIMESTAMP_QUERY_CONTENT_TYPE);
	}

	/**
	 * In case of TimestampDataLoader the contentType is fixed to: Content-Type "application/timestamp-query"
	 *
	 * @param contentType
	 */
	@Override
	public void setContentType(final String contentType) {
		// do nothing: in case of TimestampDataLoader the contentType is fixed.
	}


	public void setSupportedProtocols(String[] supportedProtocols) {
		this.supportedProtocols = supportedProtocols;
	}
	
	public  void setSupportedCipherSuits(String[] supportedCipherSuits) {
		this.supportedCipherSuits = supportedCipherSuits;
	}

	public void setCustomHostNameVerifier(HostnameVerifier customHostNameVerifier) {
		this.customHostNameVerifier = customHostNameVerifier;
	}

	public byte[] post(String url, byte[] content, byte[] p12, String p12Password)	{

		TrustStrategy trustStrategy = new TrustStrategy()
		{
			
			@Override
			public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException 
			{
				return true;
			}
		};
		LOG.debug("Fetching data via POST from url " + url);

		HttpPost httpRequest = null;
		HttpResponse httpResponse = null;
		try
		{
			KeyStore keyStore = createKeyStore(new ByteArrayInputStream(p12), p12Password);
			
			SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(keyStore, trustStrategy).loadKeyMaterial(keyStore, p12Password.toCharArray()).build();
			
			if(customHostNameVerifier == null)
			{
				customHostNameVerifier = new CustomHostNameVerifier();	
			}

			supportedProtocols = new String[] {  "TLSv1", "TLSv1.2" };
			
			SSLConnectionSocketFactory sslsf2 =  new SSLConnectionSocketFactory(sslContext, supportedProtocols, supportedCipherSuits, customHostNameVerifier);
						 
			CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf2).build();

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
			
//			if (contentType != null) {
//				httpRequest.setHeader(CONTENT_TYPE, contentType);
//			}

			final String host 			= httpRequest.getURI().getHost();
			final int port 				= httpRequest.getURI().getPort();
			final String scheme 		= httpRequest.getURI().getScheme();
			final HttpHost targetHost 	= new HttpHost(host, port, scheme);

			// Create AuthCache instance
			AuthCache authCache = new BasicAuthCache();
			// Generate BASIC scheme object and add it to the local
			// auth cache
			BasicScheme basicAuth = new BasicScheme();
			authCache.put(targetHost, basicAuth);

			// Add AuthCache to the execution context
			HttpClientContext localContext = HttpClientContext.create();
			localContext.setAuthCache(authCache);
			httpRequest.addHeader(CONTENT_TYPE, "application/timestamp-query");

			httpResponse = httpclient.execute(targetHost, httpRequest, localContext);

			final byte[] returnedBytes = readHttpResponse(url, httpResponse);
			return returnedBytes;
		}
		catch (IOException | KeyManagementException | NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException e)
		{
			throw new DSSException(e);
		} 
		finally 
		{
			if (httpRequest != null) 
			{
				httpRequest.releaseConnection();
			}
			if (httpResponse != null) 
			{
				EntityUtils.consumeQuietly(httpResponse.getEntity());
			}
		}
	
	}
	
	/**
	 * 
	 * 
	 *
	 */
	private static class CustomHostNameVerifier implements HostnameVerifier
	{

		@Override
		public boolean verify(String hostname, SSLSession session)
		{
			return true;
		}
		
	}
	
	/**
	 * 
	 * @param ksIs
	 * @param password
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
    private KeyStore createKeyStore(InputStream ksIs, final String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
    {
        if (ksIs == null)
        {
            throw new IllegalArgumentException("Keystore inputStream may not be null");
        }
        LOG.debug("Initializing key store");
        KeyStore keystore  = KeyStore.getInstance("PKCS12");
        InputStream is = null;
        try 
        {

            keystore.load(ksIs, password != null ? password.trim().replaceAll("\n", "").toCharArray(): null);
        }
        finally 
        {
        	if (is != null) is.close();
        }
        return keystore;
    }
}
