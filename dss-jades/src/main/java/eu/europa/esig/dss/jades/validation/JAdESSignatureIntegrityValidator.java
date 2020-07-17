package eu.europa.esig.dss.jades.validation;

import java.security.PublicKey;

import org.jose4j.lang.JoseException;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;

public class JAdESSignatureIntegrityValidator extends SignatureIntegrityValidator {
	
	private final JWS jws;
	
	public JAdESSignatureIntegrityValidator(final JWS jws) {
		this.jws = jws;
	}

	@Override
	protected boolean verify(PublicKey publicKey) throws DSSException {
		try {
			jws.setKey(publicKey);
			return jws.verifySignature();
		} catch (JoseException e) {
			throw new DSSException(e);
		}
	}

}
