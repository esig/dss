package eu.europa.esig.dss.asic.validation;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.x509.CertificatePool;

public class CMSDocumentForASiCValidator extends CMSDocumentValidator implements ASiCSignatureValidator {

	public CMSDocumentForASiCValidator(DSSDocument signature) {
		super(signature);
	}

	public void setValidationCertPool(CertificatePool validationCertPool) {
		this.validationCertPool = validationCertPool;
	}

}
