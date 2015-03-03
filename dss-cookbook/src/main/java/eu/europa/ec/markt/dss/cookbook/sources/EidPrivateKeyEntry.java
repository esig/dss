package eu.europa.ec.markt.dss.cookbook.sources;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
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

	public EidPrivateKeyEntry(CertificateToken certificate, List<X509Certificate> signatureChain) {

		this.certificate = certificate;
		certificateChain = new CertificateToken[signatureChain.size()];
		certificateChain = signatureChain.toArray(certificateChain);
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
