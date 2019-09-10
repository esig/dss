package eu.europa.esig.dss.ws.timestamp.remote.rest.client;

import java.io.Serializable;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;

/**
 * This REST interface provides operations for the timestamp creation.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestTimestampService extends Serializable {
	
	/**
	 * Method used to create a timestamp
	 * @param digest {@link DigestDTO} digest to be timestamped
	 * @return {@link TimestampResponseDTO}
	 */
	@POST
	@Path("getTimestampResponse")
	TimestampResponseDTO getTimestampResponse(final DigestDTO digest);

}
