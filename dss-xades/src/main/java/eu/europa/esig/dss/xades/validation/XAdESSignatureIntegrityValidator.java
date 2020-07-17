package eu.europa.esig.dss.xades.validation;

import java.security.PublicKey;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;

public class XAdESSignatureIntegrityValidator extends SignatureIntegrityValidator {
	
	private final XMLSignature santuarioSignature;
	
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
