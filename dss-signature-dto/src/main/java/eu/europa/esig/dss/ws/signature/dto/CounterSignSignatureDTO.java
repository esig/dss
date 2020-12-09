package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Objects;

/**
 * This class is a DTO to transfer required objects to execute counterSignSignature method
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation)
 */
@SuppressWarnings("serial")
public class CounterSignSignatureDTO extends AbstractSignDocumentDTO {

	/** The document containing a signature to be counter signed */
	private RemoteDocument signatureDocument;

	/**
	 * Empty constructor
	 */
	public CounterSignSignatureDTO() {
		super(null, null);
	}

	/**
	 * Default constructor
	 *
	 * @param signatureDocument {@link RemoteDocument} with a signature to counter sign
	 * @param parameters {@link RemoteSignatureParameters}
	 * @param signatureValue {@link SignatureValueDTO}
	 */
	public CounterSignSignatureDTO(RemoteDocument signatureDocument, RemoteSignatureParameters parameters,
			SignatureValueDTO signatureValue) {
		super(parameters, signatureValue);
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
		CounterSignSignatureDTO other = (CounterSignSignatureDTO) obj;
		if (!Objects.equals(signatureDocument, other.signatureDocument)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "CounterSignSignatureDTO [signatureDocument=" + signatureDocument + ", parameters=" + getParameters()
				+ ", signatureValue=" + getSignatureValue() + "]";
	}

}
