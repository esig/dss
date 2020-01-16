package eu.europa.esig.dss.ws.signature.dto;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

/**
 * This class is a DTO that contains a set of parameters needed for a single document timestamping
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation)
 */
public class TimestampOneDocumentDTO extends AbstractTimestampDocumentDTO {
	
	private RemoteDocument toTimestampDocument;
	
	public TimestampOneDocumentDTO() {
	}
	
	public TimestampOneDocumentDTO(RemoteDocument toTimestampDocument, RemoteTimestampParameters timestampParameters) {
		super(timestampParameters);
		this.toTimestampDocument = toTimestampDocument;
	}

	public RemoteDocument getToTimestampDocument() {
		return toTimestampDocument;
	}

	public void setToTimestampDocument(RemoteDocument toTimestampDocument) {
		this.toTimestampDocument = toTimestampDocument;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((timestampParameters == null) ? 0 : timestampParameters.hashCode());
		result = (prime * result) + ((toTimestampDocument == null) ? 0 : toTimestampDocument.hashCode());
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
		TimestampOneDocumentDTO other = (TimestampOneDocumentDTO) obj;
		if (timestampParameters == null) {
			if (other.timestampParameters != null) {
				return false;
			}
		} else if (!timestampParameters.equals(other.timestampParameters)) {
			return false;
		}
		if (toTimestampDocument == null) {
			if (other.toTimestampDocument != null) {
				return false;
			}
		} else if (!toTimestampDocument.equals(other.toTimestampDocument)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "TimestampOneDocumentDTO [toTimestampDocument=" + toTimestampDocument + ", parameters=" + timestampParameters + "]";
	}

}
