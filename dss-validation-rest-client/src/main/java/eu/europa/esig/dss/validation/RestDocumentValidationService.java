package eu.europa.esig.dss.validation;

import java.io.Serializable;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import eu.europa.esig.dss.validation.reports.dto.DataToValidateDTO;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

/**
 * This REST interface provides operations for the validation of signature.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestDocumentValidationService extends Serializable {

	/**
	 * This method returns the result of the validation of the signed file. The results contains a Diagnostic Data, a
	 * simple report and a detailed report
	 * 
	 * @param dataToValidate
	 * @return
	 */
	@POST
	@Path("validateSignature")
	ReportsDTO validateSignature(DataToValidateDTO dataToValidate);

}
