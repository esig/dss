package eu.europa.esig.dss.validation;

import java.io.Serializable;
import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import eu.europa.esig.dss.DataToValidateDTO;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

/**
 * This REST interface provides operations for the validation of signature.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestDocumentValidationService extends Serializable {

	/**
	 * This method returns the result of the validation of the signed file. The
	 * results contains a Diagnostic Data, a simple report and a detailed report
	 * 
	 * @param dataToValidate
	 *                       a {@code DataToValidateDTO} which contains the
	 *                       signature, the optional original document and the
	 *                       optional validation policy
	 * @return a {@code ReportsDTO} with the 3 reports : the diagnostic data, the
	 *         detailed report and the simple report
	 */
	@POST
	@Path("validateSignature")
	ReportsDTO validateSignature(DataToValidateDTO dataToValidate);

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
	@POST
	@Path("getOriginalDocuments")
	List<RemoteDocument> getOriginalDocuments(DataToValidateDTO dataToValidate);

}
