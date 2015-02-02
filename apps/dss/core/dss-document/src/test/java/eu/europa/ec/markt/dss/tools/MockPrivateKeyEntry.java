package eu.europa.ec.markt.dss.tools;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;

public class MockPrivateKeyEntry implements DSSPrivateKeyEntry {

	private final EncryptionAlgorithm encryptionAlgo;
	private final X509Certificate certificate;
	private final X509Certificate[] certificateChain;
	private final PrivateKey privateKey;

	public MockPrivateKeyEntry(EncryptionAlgorithm encryptionAlgo, X509Certificate certificate, PrivateKey privateKey) {
		this.encryptionAlgo = encryptionAlgo;
		this.certificate = certificate;
		this.privateKey = privateKey;
		this.certificateChain = null;
	}

	public MockPrivateKeyEntry(EncryptionAlgorithm encryptionAlgo, X509Certificate certificate, X509Certificate[] certificateChain,
			PrivateKey privateKey) {
		this.encryptionAlgo = encryptionAlgo;
		this.certificate = certificate;
		this.certificateChain = certificateChain;
		this.privateKey = privateKey;
	}

	@Override
	public X509Certificate getCertificate() {
		return certificate;
	}

	@Override
	public X509Certificate[] getCertificateChain() {
		return certificateChain;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() throws DSSException {
		return encryptionAlgo;
	}

	@Override
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

}
