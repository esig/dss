package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;

import java.security.PublicKey;

/**
 * Verifies integrity of a XAdES signature
 */
public class XAdESSignatureIntegrityValidator extends SignatureIntegrityValidator {

	/** The relevant Santuario signature instance */
	private final XMLSignature santuarioSignature;

	/**
	 * Default constructor
	 *
	 * @param santuarioSignature {@link XMLSignature}
	 */
	public XAdESSignatureIntegrityValidator(XMLSignature santuarioSignature) {
		this.santuarioSignature = santuarioSignature;
	}

	@Override
	protected boolean verify(PublicKey publicKey) throws DSSException {
		try {
			return santuarioSignature.checkSignatureValue(publicKey);
		} catch (XMLSignatureException e) {
			throw new DSSException(e);
		}
	}

}
