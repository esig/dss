package eu.europa.esig.dss.asic.validation;

import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.x509.CertificatePool;

public interface ASiCSignatureValidator extends DocumentValidator {

	/**
	 * This method allows to share the certificate pool between signature validations
	 * 
	 * @param validationCertPool
	 *            the certificate pool
	 */
	void setValidationCertPool(CertificatePool validationCertPool);

}
