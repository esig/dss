package eu.europa.esig.dss.validation;

import java.io.Serializable;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.validation.reports.dto.DataToValidateDTO;

/**
 * The validation web service allow to validate the signature inside a signed file. In addition, the original file and a
 * specific policy can be passed to perform the validation.
 * 
 */
@WebService(targetNamespace = "http://validation.dss.esig.europa.eu/")
public interface SoapDocumentValidationService extends Serializable {

	/**
	 * This method returns the result of the validation of the signed file. The results contains a Diagnostic Data, a
	 * simple report and a detailed report
	 * 
	 * @param dataToValidate
	 * @return
	 */
	@WebResult(name = "WSReportsDTO")
	WSReportsDTO validateSignature(@WebParam(name = "dataToValidateDTO") DataToValidateDTO dataToValidate);
}
