package eu.europa.esig.dss.service.http.commons;

import java.io.IOException;
import java.io.Serializable;
import java.net.URISyntaxException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLSession;

import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;

/**
 * The data loader which includes server webpage certificates to the response context
 * Use the method getCertificates(url) to extract the data
 *
 */
public class SSLCertificateLoader implements Serializable {

	private static final long serialVersionUID = -2560386894555266018L;

	private static final Logger LOG = LoggerFactory.getLogger(SSLCertificateLoader.class);

    public static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
    
    /* A proxied CommonsDataLoader to be used */
    private CommonsDataLoader commonsDataLoader;

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
     * @throws DSSException in case if an exception occurs
     */
    public List<CertificateToken> getCertificates(final String urlString) throws DSSException {
    	if (Protocol.isHttpUrl(urlString)) {
			Certificate[] httpGetCertificates = httpGetCertificates(urlString);
			return toCertificateTokens(httpGetCertificates);
    	}
		throw new DSSException("DSS framework only supports HTTP(S) certificate extraction");
    }
    
    private Certificate[] httpGetCertificates(final String url) throws DSSException {
    	HttpGet httpRequest = null;
		CloseableHttpResponse httpResponse = null;
		CloseableHttpClient client = null;
		
		try {
			httpRequest = getCommonsDataLoader().getHttpRequest(url);
			client = getHttpClient(url);

			final HttpHost targetHost = getCommonsDataLoader().getHttpHost(httpRequest);
			final HttpContext localContext = getCommonsDataLoader().getHttpContext(targetHost);
			httpResponse = client.execute(targetHost, httpRequest, localContext);

			return readCertificates(localContext);

		} catch (URISyntaxException | IOException e) {
			throw new DSSExternalResourceException(String.format("Unable to process GET call for url [%s]. Reason : [%s]", url, DSSUtils.getExceptionMessage(e)), e);
		
		} finally {
			getCommonsDataLoader().closeQuietly(httpRequest, httpResponse, client);
		
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
		httpClientBuilder.addInterceptorLast(getHttpResponseInterceptor());
		return httpClientBuilder.build();
	}
	
	private HttpResponseInterceptor getHttpResponseInterceptor() {
		return new HttpResponseInterceptor() {
			@Override
			public void process(HttpResponse response, HttpContext context) throws HttpException, IOException {
				ManagedHttpClientConnection routedConnection = (ManagedHttpClientConnection)context.getAttribute(HttpCoreContext.HTTP_CONNECTION);
	            SSLSession sslSession = routedConnection.getSSLSession();
	            if (sslSession != null) {
	                Certificate[] certificates = sslSession.getPeerCertificates();
	                context.setAttribute(PEER_CERTIFICATES, certificates);
	            }
			}
		};
	}

}
