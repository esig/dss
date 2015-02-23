package eu.europa.ec.markt.dss.mock;

import java.security.PrivateKey;

import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

public class MockPrivateKeyEntry implements DSSPrivateKeyEntry {

	private final EncryptionAlgorithm encryptionAlgo;
	private final CertificateToken certificate;
	private final CertificateToken[] certificateChain;
	private final PrivateKey privateKey;

	public MockPrivateKeyEntry(EncryptionAlgorithm encryptionAlgo, CertificateToken certificate, PrivateKey privateKey) {
		this.encryptionAlgo = encryptionAlgo;
		this.certificate = certificate;
		this.privateKey = privateKey;
		this.certificateChain = null;
	}

	public MockPrivateKeyEntry(EncryptionAlgorithm encryptionAlgo, CertificateToken certificate, CertificateToken[] certificateChain,
			PrivateKey privateKey) {
		this.encryptionAlgo = encryptionAlgo;
		this.certificate = certificate;
		this.certificateChain = certificateChain;
		this.privateKey = privateKey;
	}

	@Override
	public CertificateToken getCertificate() {
		return certificate;
	}

	@Override
	public CertificateToken[] getCertificateChain() {
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
