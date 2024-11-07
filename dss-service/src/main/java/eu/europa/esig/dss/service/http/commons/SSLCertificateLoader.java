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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.HttpResponseInterceptor;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * The data loader which includes server webpage certificates to the response context
 * Use the method getCertificates(url) to extract the data
 *
 */
public class SSLCertificateLoader implements Serializable {

	private static final long serialVersionUID = -2560386894555266018L;

	private static final Logger LOG = LoggerFactory.getLogger(SSLCertificateLoader.class);

	/** The attribute containing a certificate chain */
	private static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
    
    /** A proxied CommonsDataLoader to be used */
    private CommonsDataLoader commonsDataLoader;

	/**
	 * Default constructor with null CommonsDataLoader
	 */
	public SSLCertificateLoader() {
		// empty
	}

	/**
	 * Allows to set a pre-configured CommonsDataLoader
	 * 
	 * @param commonsDataLoader {@link CommonsDataLoader} to use
	 */
	public void setCommonsDataLoader(CommonsDataLoader commonsDataLoader) {
		this.commonsDataLoader = commonsDataLoader;
	}

	private CommonsDataLoader getCommonsDataLoader() {
		if (commonsDataLoader == null) {
			commonsDataLoader = new CommonsDataLoader();
		}
		return commonsDataLoader;
	}
    
    /**
     * The method to extract SSL-certificates from the given web page
     * 
     * @param urlString {@link String} representing a URL of a webpage with a secure connection (HTTPS)
     * @return a {@link CertificateToken} chain of the secure webpage
     */
    public List<CertificateToken> getCertificates(final String urlString) {
    	final String trimmedUrl = Utils.trim(urlString);
    	if (Protocol.isHttpUrl(trimmedUrl)) {
			Certificate[] httpGetCertificates = httpGetCertificates(trimmedUrl);
			return toCertificateTokens(httpGetCertificates);
    	}
		throw new UnsupportedOperationException(String.format(
				"DSS framework supports only HTTP(S) certificate extraction. Obtained URL : '%s'", urlString));
    }

    private Certificate[] httpGetCertificates(final String url) throws DSSException {
    	HttpGet httpRequest = null;
		CloseableHttpClient client = null;
		
		final CommonsDataLoader dataLoader = getCommonsDataLoader();
		try {
			httpRequest = dataLoader.getHttpRequest(url);
			client = getHttpClient(url);

			final HttpHost targetHost = dataLoader.getHttpHost(httpRequest);
			final HttpContext localContext = dataLoader.getHttpContext(targetHost);
			final NoSenseHttpClientResponseHandler httpClientResponseHandler = new NoSenseHttpClientResponseHandler();
			client.execute(targetHost, httpRequest, localContext, httpClientResponseHandler);

			return readCertificates(localContext);

		} catch (Exception e) {
			throw new DSSExternalResourceException(String.format("Unable to process GET call for url [%s]. " +
					"Reason : [%s]", url, DSSUtils.getExceptionMessage(e)), e);
		
		} finally {
			dataLoader.closeQuietly(httpRequest, client);
		}
    }
    
    private List<CertificateToken> toCertificateTokens(Certificate[] certificates) {
    	List<CertificateToken> certificateTokens = new ArrayList<>();
    	for (Certificate certificate : certificates) {
    		try {
				certificateTokens.add(DSSUtils.loadCertificate(certificate.getEncoded()));
			} catch (CertificateEncodingException e) {
				LOG.warn("Cannot read and/or create an instance of a CertificateToken for a certificate : '{}'. "
						+ "The entry is skipped. Reason : {}", certificate, e.getMessage());
			}
    	}
    	return certificateTokens;
    }
    
    private Certificate[] readCertificates(HttpContext context) {
    	Object attribute = context.getAttribute(PEER_CERTIFICATES);
    	if (attribute instanceof Certificate[]) {
    		return (Certificate[]) attribute;
    	}
    	return new Certificate[] {};
    }
    
    private synchronized CloseableHttpClient getHttpClient(final String url) {
		HttpClientBuilder httpClientBuilder = getCommonsDataLoader().getHttpClientBuilder(url);
		httpClientBuilder.addResponseInterceptorLast(getHttpResponseInterceptor());
		return httpClientBuilder.build();
	}
	
	private HttpResponseInterceptor getHttpResponseInterceptor() {
		return new HttpResponseInterceptor() {

			@Override
			public void process(HttpResponse httpResponse, EntityDetails entityDetails, HttpContext httpContext) throws IOException {
				SSLSession sslSession = (SSLSession) httpContext.getAttribute(HttpCoreContext.SSL_SESSION);
				if (sslSession != null) {
					Certificate[] certificates = sslSession.getPeerCertificates();
					httpContext.setAttribute(PEER_CERTIFICATES, certificates);
				}
			}

		};
	}

	/**
	 * This class consumes the {@code ClassicHttpResponse} but does not process or return any content.
	 * It is used to quickly process a response without a need to extract any data.
	 */
	private static class NoSenseHttpClientResponseHandler implements HttpClientResponseHandler<byte[]> {

		@Override
		public byte[] handleResponse(ClassicHttpResponse classicHttpResponse) throws HttpException, IOException {
			if (classicHttpResponse != null) {
				EntityUtils.consumeQuietly(classicHttpResponse.getEntity());
				Utils.closeQuietly(classicHttpResponse);
			}
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}

	}


}
