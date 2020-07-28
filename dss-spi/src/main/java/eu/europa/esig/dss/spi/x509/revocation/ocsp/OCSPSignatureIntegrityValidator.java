package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import java.security.PublicKey;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;

public class OCSPSignatureIntegrityValidator extends SignatureIntegrityValidator {
	
	private final OCSPToken ocspToken;
	
	public OCSPSignatureIntegrityValidator(final OCSPToken ocspToken) {
		this.ocspToken = ocspToken;
	}

	@Override
	protected boolean verify(PublicKey publicKey) throws DSSException {
		return ocspToken.isSignedBy(publicKey);
	}

}
