package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import org.jose4j.lang.JoseException;

import java.security.PublicKey;

/**
 * Checks the integrity of a JAdES SignatureValue
 */
public class JAdESSignatureIntegrityValidator extends SignatureIntegrityValidator {

	/** The JWS signature to validate */
	private final JWS jws;

	/**
	 * Default constructor
	 *
	 * @param jws {@link JWS}
	 */
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
