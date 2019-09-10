package eu.europa.esig.dss.ws.timestamp.remote.rest;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;
import eu.europa.esig.dss.ws.timestamp.remote.RemoteTimestampService;
import eu.europa.esig.dss.ws.timestamp.remote.rest.client.RestTimestampService;

public class RestTimestampServiceImpl implements RestTimestampService {
	
	private static final long serialVersionUID = -9029828318368575716L;
	
	private RemoteTimestampService timestampService;
	
	public void setTimestampService(RemoteTimestampService timestampService) {
		this.timestampService = timestampService;
	}

	@Override
	public TimestampResponseDTO getTimestampResponse(final DigestDTO digest) {
		return timestampService.getTimestampResponse(digest.getAlgorithm(), digest.getValue());
	}

}
