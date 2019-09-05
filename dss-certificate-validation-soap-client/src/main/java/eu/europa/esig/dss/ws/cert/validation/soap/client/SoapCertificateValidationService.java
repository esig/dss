package eu.europa.esig.dss.ws.cert.validation.soap.client;

import java.io.Serializable;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;

/**
 * The validation web service allow to validate the provided certificate. Missing certificate from certificate chain
 * and a custom validation time can be provided.
 */
@WebService(targetNamespace = "http://certificate-validation.dss.esig.europa.eu/")
public interface SoapCertificateValidationService extends Serializable {

	/**
	 * This method returns the result of the validation of the certificate. The
	 * results contains a Diagnostic Data, simple certificate report and detailed report
	 * 
	 * @param certificateToValidate
	 *                       a {@code CertificateToValidateDTO} which contains the
	 *                       certificate, the certificate chain and validation time
	 * @return a {@code WSCertificateReportsDTO} with the 3 reports : the diagnostic data, the
	 *         detailed report and the simple certificate report
	 */
	@WebResult(name = "WSReportsDTO")
	WSCertificateReportsDTO validateCertificate(@WebParam(name = "dataToValidateDTO") CertificateToValidateDTO certificateToValidate);

}
