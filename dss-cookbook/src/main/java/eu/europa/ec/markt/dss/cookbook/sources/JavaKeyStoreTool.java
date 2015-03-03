package eu.europa.ec.markt.dss.cookbook.sources;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.token.KSPrivateKeyEntry;

public class JavaKeyStoreTool {

	protected KeyStore ks = null;

	public JavaKeyStoreTool(final String ksUrlLocation, final String ksPassword) {

		InputStream ksStream = null;
		try {
			final URL ksLocation = new URL(ksUrlLocation);
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ksStream = ksLocation.openStream();
			ks.load(ksStream, (ksPassword == null) ? null : ksPassword.toCharArray());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} finally {
			DSSUtils.closeQuietly(ksStream);
		}
	}

	public X509Certificate getCertificate(String certAlias, String password) {

		try {

			Certificate cert = ks.getCertificate(certAlias);
			if (cert == null) {
				return null;
			}
			if (!(cert instanceof X509Certificate)) {
				return null;
			}
			return (X509Certificate) cert;
		} catch (KeyStoreException e) {

			throw new DSSException(e);
		}
	}

	public KSPrivateKeyEntry getPrivateKey(String certAlias, String password) {

		try {

			final Key key = ks.getKey(certAlias, password.toCharArray());
			if (key == null) {
				return null;
			}
			if (!(key instanceof PrivateKey)) {
				return null;
			}
			final Certificate[] certificateChain = ks.getCertificateChain(certAlias);
			KeyStore.PrivateKeyEntry privateKey = new KeyStore.PrivateKeyEntry((PrivateKey) key, certificateChain);
			KSPrivateKeyEntry ksPrivateKey = new KSPrivateKeyEntry(privateKey);
			return ksPrivateKey;
		} catch (KeyStoreException e) {
			throw new DSSException(e);
		} catch (UnrecoverableKeyException e) {
			throw new DSSException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new DSSException(e);
		}
	}
}
