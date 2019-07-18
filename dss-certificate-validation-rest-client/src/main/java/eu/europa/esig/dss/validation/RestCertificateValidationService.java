package eu.europa.esig.dss.validation;
import java.io.Serializable;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import eu.europa.esig.dss.dto.CertificateReportsDTO;
import eu.europa.esig.dss.dto.CertificateToValidateDTO;

/**
 * This REST interface provides operations for the validation of certificate.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestCertificateValidationService extends Serializable {

	/**
	 * This method returns the result of the validation of the signed file. The
	 * results contains a Diagnostic Data, simple certificate report and detailed report
	 * 
	 * @param certificateToValidate
	 *                       a {@code CertificateToValidateDTO} which contains the
	 *                       certificate, certificate chain and validation time
	 * @return a {@code CertificateReportsDTO} with the 3 reports : the diagnostic data, the
	 *         detailed report and the simple certificate report
	 */
	@POST
	@Path("validateCertificate")
	CertificateReportsDTO validateCertificate(CertificateToValidateDTO certificateToValidate);

}
