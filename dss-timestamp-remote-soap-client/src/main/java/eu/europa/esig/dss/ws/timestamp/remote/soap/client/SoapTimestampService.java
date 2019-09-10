package eu.europa.esig.dss.ws.timestamp.remote.soap.client;

import java.io.Serializable;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;

/**
 * The SOAP web service allows timestamp creation.
 */
@WebService(targetNamespace = "http://timestamp.dss.esig.europa.eu/")
public interface SoapTimestampService extends Serializable {
	
	/**
	 * Requests a timestamp binaries by the provided digest to be timestamped
	 * @param digest {@link DigestDTO} to timestamp
	 * @return {@link TimestampResponseDTO}
	 */
	@WebResult(name = "TimestampResponseDTO")
	TimestampResponseDTO getTimestampResponse(@WebParam(name = "digest") DigestDTO digest);

}
