package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

public class AbstractTimestampDocumentDTO {
	
	protected RemoteTimestampParameters timestampParameters;
	
	public AbstractTimestampDocumentDTO() {
	}
	
	public AbstractTimestampDocumentDTO(RemoteTimestampParameters timestampParameters) {
		this.timestampParameters = timestampParameters;
	}

	public RemoteTimestampParameters getTimestampParameters() {
		return timestampParameters;
	}

	public void setTimestampParameters(RemoteTimestampParameters timestampParameters) {
		this.timestampParameters = timestampParameters;
	}

}
