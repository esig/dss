package eu.europa.esig.dss.validation;

import java.io.Serializable;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import org.apache.cxf.annotations.WSDLDocumentation;

import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

@WebService
@WSDLDocumentation("The validation web service allow to validate the signature inside a signed file. "
		+ "In addition, the original file and a specific policy can be passed to perform the validation.")
public interface SoapDocumentValidationService extends Serializable {

	@WSDLDocumentation("This method returns the result of the validation of the signed file. The results contains a Diagnostic Data, a simple report and a detailed report")
	@WebResult(name = "response")
	ReportsDTO validateSignature(@WebParam(name = "signedFile") RemoteDocument signedFile, 
			@WebParam(name = "originalFile") RemoteDocument originalFile, @WebParam(name = "policy" ) ConstraintsParameters policy);
}
