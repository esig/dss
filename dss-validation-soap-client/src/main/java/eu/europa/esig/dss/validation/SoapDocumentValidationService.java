package eu.europa.esig.dss.validation;

import java.io.Serializable;
import java.util.List;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.DataToValidateDTO;
import eu.europa.esig.dss.RemoteDocument;

/**
 * The validation web service allow to validate the signature inside a signed file. In addition, the original file and a
 * specific policy can be passed to perform the validation.
 * 
 */
@WebService(targetNamespace = "http://validation.dss.esig.europa.eu/")
public interface SoapDocumentValidationService extends Serializable {

	/**
	 * This method returns the result of the validation of the signed file. The
	 * results contains a Diagnostic Data, a simple report and a detailed report
	 * 
	 * @param dataToValidate
	 *                       a {@code DataToValidateDTO} which contains the
	 *                       signature, the optional original document(s) and the
	 *                       optional validation policy
	 * @return a {@code WSReportsDTO} with the 3 reports : the diagnostic data, the
	 *         detailed report and the simple report
	 */
	@WebResult(name = "WSReportsDTO")
	WSReportsDTO validateSignature(@WebParam(name = "dataToValidateDTO") DataToValidateDTO dataToValidate);

	/**
	 * This method returns the original document(s) for the given signed file and
	 * optionally the signatureId.
	 * 
	 * @param dataToValidate
	 *                       a {@code DataToValidateDTO} which contains the
	 *                       signature, the optional original document and the
	 *                       optional signatureId
	 * @return a List of {@code RemoteDocument}
	 */
	@WebResult(name = "WSOriginalDocuments")
	List<RemoteDocument> getOriginalDocuments(@WebParam(name = "dataToValidateDTO") DataToValidateDTO dataToValidate);

}
