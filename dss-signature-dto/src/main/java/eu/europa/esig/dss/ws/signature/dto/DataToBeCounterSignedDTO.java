package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Objects;

/**
 * This class is a DTO to transfer required objects to execute getDataToBeCounterSigned method 
 * It's only possible to transfer an object by POST and REST. 
 * It's impossible to transfer big objects by GET (url size limitation)
 */
@SuppressWarnings("serial")
public class DataToBeCounterSignedDTO extends AbstractDataToSignDTO {

	/** Document containing a signature to be counter signed */
	private RemoteDocument signatureDocument;

	/**
	 * Empty constructor
	 */
	public DataToBeCounterSignedDTO() {
		super(null);
	}

	/**
	 * Default constructor
	 *
	 * @param signatureDocument {@link RemoteDocument} with a signature to counter sign
	 * @param parameters {@link RemoteSignatureParameters}
	 */
	public DataToBeCounterSignedDTO(RemoteDocument signatureDocument, RemoteSignatureParameters parameters) {
		super(parameters);
		this.setSignatureDocument(signatureDocument);
	}

	/**
	 * Gets the signature document
	 *
	 * @return {@link RemoteDocument}
	 */
	public RemoteDocument getSignatureDocument() {
		return signatureDocument;
	}

	/**
	 * Sets the signature document
	 *
	 * @param signatureDocument {@link RemoteDocument}
	 */
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
