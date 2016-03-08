package eu.europa.esig.dss.validation;

import java.io.Serializable;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.cxf.jaxrs.model.wadl.Description;

import eu.europa.esig.dss.validation.reports.dto.DataToValidateDTO;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

@Path("ValidationService")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Description(value = "This REST interface provides operations for the validation of signature.")
public interface RestDocumentValidationService extends Serializable {

	@POST
	@Path("validateSignature")
	ReportsDTO validateSignature(DataToValidateDTO dataToValidate);
}
