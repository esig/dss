package eu.europa.esig.dss.validation;

import java.io.Serializable;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.cxf.jaxrs.model.wadl.Description;

import com.sun.istack.Nullable;

import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.reports.dto.ValidationResultDTO;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

@Path("ValidationService")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Description(value = "This REST interface provides operations for the validation of signature.")
public interface RestDocumentValidationService extends Serializable {

	@POST
	@Path("validateSignature")
	ValidationResultDTO validateSignature(@PathParam("signedFile") RemoteDocument signedFile, 
			@PathParam("originalFile") @Nullable RemoteDocument originalFile, @PathParam("policy") @Nullable ConstraintsParameters policy);
}
