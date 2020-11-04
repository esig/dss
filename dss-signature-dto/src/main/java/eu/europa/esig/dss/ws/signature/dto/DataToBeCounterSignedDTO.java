package eu.europa.esig.dss.ws.signature.dto;

import java.util.Objects;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

/**
 * This class is a DTO to transfer required objects to execute getDataToBeCounterSigned method 
 * It's only possible to transfer an object by POST and REST. 
 * It's impossible to transfer big objects by GET (url size limitation)
 */
@SuppressWarnings("serial")
public class DataToBeCounterSignedDTO extends AbstractDataToSignDTO {

	private RemoteDocument signatureDocument;

	public DataToBeCounterSignedDTO() {
		super(null);
	}

	public DataToBeCounterSignedDTO(RemoteDocument signatureDocument, RemoteSignatureParameters parameters) {
		super(parameters);
		this.setSignatureDocument(signatureDocument);
	}

	public RemoteDocument getSignatureDocument() {
		return signatureDocument;
	}

	public void setSignatureDocument(RemoteDocument signatureDocument) {
		this.signatureDocument = signatureDocument;
	}

	@Override
	public String toString() {
		return "DataToCounterSignDTO [signatureDocument=" + signatureDocument + ", parameters()=" + getParameters() + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((signatureDocument == null) ? 0 : signatureDocument.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		DataToBeCounterSignedDTO other = (DataToBeCounterSignedDTO) obj;
		if (!Objects.equals(signatureDocument, other.signatureDocument)) {
			return false;
		}
		return true;
	}

}
