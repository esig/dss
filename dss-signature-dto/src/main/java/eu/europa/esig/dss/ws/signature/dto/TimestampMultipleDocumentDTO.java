package eu.europa.esig.dss.ws.signature.dto;

import java.util.List;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

public class TimestampMultipleDocumentDTO extends AbstractTimestampDocumentDTO {
	
	private List<RemoteDocument> toTimestampDocuments;
	
	public TimestampMultipleDocumentDTO() {
	}
	
	public TimestampMultipleDocumentDTO(List<RemoteDocument> toTimestampDocuments, RemoteTimestampParameters timestampParameters) {
		super(timestampParameters);
		this.setToTimestampDocuments(toTimestampDocuments);
	}

	public List<RemoteDocument> getToTimestampDocuments() {
		return toTimestampDocuments;
	}

	public void setToTimestampDocuments(List<RemoteDocument> toTimestampDocuments) {
		this.toTimestampDocuments = toTimestampDocuments;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((timestampParameters == null) ? 0 : timestampParameters.hashCode());
		result = (prime * result) + ((toTimestampDocuments == null) ? 0 : toTimestampDocuments.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		TimestampMultipleDocumentDTO other = (TimestampMultipleDocumentDTO) obj;
		if (timestampParameters == null) {
			if (other.timestampParameters != null) {
				return false;
			}
		} else if (!timestampParameters.equals(other.timestampParameters)) {
			return false;
		}
		if (toTimestampDocuments == null) {
			if (other.toTimestampDocuments != null) {
				return false;
			}
		} else if (!toTimestampDocuments.equals(other.toTimestampDocuments)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "TimestampMultipleDocumentDTO [toTimestampDocuments=" + toTimestampDocuments + ", parameters=" + timestampParameters + "]";
	}

}
