package eu.europa.esig.dss.client.http.commons;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Default trust manager.
 * 
 * @author lodermatt
 */
public final class DefaultTrustManager implements X509TrustManager {

	/** TrustStore. */
	private X509TrustManager trustManager;

	/**
	 * @param keystore
	 * 
	 * @throws GeneralSecurityException
	 *             Certificate/Keystore/Algorithm/... exception
	 * @throws IOException
	 *             I/O Error
	 */
	public DefaultTrustManager(final KeyStore keystore) throws GeneralSecurityException, IOException {
		// initialize a new TMF with the ts we just loaded
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keystore);

		// acquire X509 trust manager from factory
		TrustManager[] tms = tmf.getTrustManagers();

		for (final TrustManager tm : tms) {
			if (tm instanceof X509TrustManager) {
				this.trustManager = (X509TrustManager) tm;
				return;
			}
		}
		throw new NoSuchAlgorithmException("No X509TrustManager in TrustManagerFactory");
	}

	/**
	 * Constructor.
	 * 
	 * @param tsInputStream
	 *            The truststore
	 * @param tsType
	 *            the trust store type
	 * @param tsPasswd
	 *            truststore password
	 *
	 * @throws GeneralSecurityException
	 *             Certificate/Keystore/Algorithm/... exception
	 * @throws IOException
	 *             I/O Error
	 */
	public DefaultTrustManager(InputStream tsInputStream, String tsType, String tsPasswd) throws GeneralSecurityException, IOException {
		// load keystore from specified cert store (or default)
		KeyStore keystore = KeyStore.getInstance(tsType);
		keystore.load(tsInputStream, tsPasswd.toCharArray());
		this.initTrustManager(keystore);
	}

	/**
	 * Loading the truststore.
	 * 
	 * @param keystore
	 *            truststore
	 * 
	 * @throws GeneralSecurityException
	 *             Certificate/Keystore/Algorithm/... exception
	 * @throws IOException
	 *             I/O Error
	 */
	private void initTrustManager(final KeyStore keystore) throws GeneralSecurityException, IOException {

		// initialize a new TMF with the ts we just loaded
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keystore);

		// acquire X509 trust manager from factory
		TrustManager[] tms = tmf.getTrustManagers();

		for (final TrustManager tm : tms) {
			if (tm instanceof X509TrustManager) {
				trustManager = (X509TrustManager) tm;
				return;
			}
		}

		throw new NoSuchAlgorithmException("No X509TrustManager in TrustManagerFactory"); //$NON-NLS-1$
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
	 */
	@Override
	public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
		trustManager.checkClientTrusted(chain, authType);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
	 */
	@Override
	public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
		trustManager.checkServerTrusted(chain, authType);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
	 */
	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return trustManager.getAcceptedIssuers();
	}

}