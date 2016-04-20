package eu.europa.esig.dss.client.http.commons;

import java.io.IOException;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;

/**
 * Default Keys Manager.
 * 
 * @author lodermatt
 */
public final class DefaultKeyManager implements X509KeyManager {

	/** KeyManager. */
	private X509KeyManager keyManager;

	/**
	 * Constructor.
	 * 
	 * @param keystore
	 *            The keystore
	 * @param ksPasswd
	 *            Keystore's password
	 * @throws UnrecoverableKeyException
	 *             Not recoverable key
	 * @throws KeyStoreException
	 *             Keystore error
	 * @throws NoSuchAlgorithmException
	 *             Algorithm not found
	 * @throws CertificateException
	 *             Certificate error
	 * @throws IOException
	 *             I/O Error
	 */
	public DefaultKeyManager(final KeyStore keystore, final String ksPasswd)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		super();
		this.initKeyManager(keystore, ksPasswd);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509KeyManager#chooseClientAlias(java.lang.String[], java.security.Principal[],
	 * java.net.Socket)
	 */
	@Override
	public String chooseClientAlias(final String[] keyType, final Principal[] issuers, final Socket socket) {
		return this.keyManager.chooseClientAlias(keyType, issuers, socket);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509KeyManager#chooseServerAlias(java.lang.String, java.security.Principal[], java.net.Socket)
	 */
	@Override
	public String chooseServerAlias(final String keyType, final Principal[] issuers, final Socket socket) {
		return this.keyManager.chooseServerAlias(keyType, issuers, socket);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509KeyManager#getCertificateChain(java.lang.String)
	 */
	@Override
	public X509Certificate[] getCertificateChain(final String alias) {
		return this.keyManager.getCertificateChain(alias);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509KeyManager#getClientAliases(java.lang.String, java.security.Principal[])
	 */
	@Override
	public String[] getClientAliases(final String keyType, final Principal[] issuers) {
		return this.keyManager.getClientAliases(keyType, issuers);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509KeyManager#getPrivateKey(java.lang.String)
	 */
	@Override
	public PrivateKey getPrivateKey(final String alias) {
		return this.keyManager.getPrivateKey(alias);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509KeyManager#getServerAliases(java.lang.String, java.security.Principal[])
	 */
	@Override
	public String[] getServerAliases(final String keyType, final Principal[] issuers) {
		return this.keyManager.getServerAliases(keyType, issuers);
	}

	/**
	 * Loads the keystore.
	 * 
	 * @param keystore
	 *            the keystore to load
	 * @param ksPasswd
	 *            keystore's password
	 * @throws UnrecoverableKeyException
	 *             Not recoverable key
	 * @throws KeyStoreException
	 *             Keystore error
	 * @throws NoSuchAlgorithmException
	 *             Algorithm not found
	 * @throws CertificateException
	 *             Certificate error
	 * @throws IOException
	 *             I/O Error
	 */
	private void initKeyManager(final KeyStore keystore, final String ksPasswd)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException { // NOPMD
		// initialize a new KMF with the ts we just loaded
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keystore, ksPasswd.toCharArray());

		// acquire X509 key manager from factory
		final KeyManager[] kms = kmf.getKeyManagers();

		for (final KeyManager km : kms) {
			if (km instanceof X509KeyManager) {
				this.keyManager = (X509KeyManager) km;
				return;
			}
		}
		throw new NoSuchAlgorithmException("No X509KeyManager in KeyManagerFactory");
	}
}