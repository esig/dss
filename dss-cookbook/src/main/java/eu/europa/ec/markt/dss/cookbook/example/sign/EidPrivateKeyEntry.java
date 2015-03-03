package eu.europa.ec.markt.dss.cookbook.example.sign;

import java.security.PrivateKey;
import java.util.List;

import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * Sample for eID
 *
 */
public class EidPrivateKeyEntry implements DSSPrivateKeyEntry {

	private CertificateToken certificate;

	private CertificateToken[] certificateChain;

	public EidPrivateKeyEntry(CertificateToken certificate, List<CertificateToken> chain) {

		this.certificate = certificate;
		certificateChain = new CertificateToken[chain.size()];
		certificateChain = chain.toArray(certificateChain);
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
		return null;
	}

	@Override
	public PrivateKey getPrivateKey() {
		return null;
	}
}
