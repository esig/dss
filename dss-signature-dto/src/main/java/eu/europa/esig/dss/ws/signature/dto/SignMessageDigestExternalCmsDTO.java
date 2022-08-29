package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Objects;

/**
 * Represents a DataTransferObject containing the required parameters for creation of a CMS signature (CMSSignedData)
 * suitable for PAdES signing (to be enveloped within PDF signature revision).
 * <p>
 * It's only possible to transfer an object by POST and REST.
 *
 */
public class SignMessageDigestExternalCmsDTO extends AbstractSignDocumentDTO {

    private static final long serialVersionUID = -4212141706198393826L;

    /** Message-digest computed in PDF signature ByteRange */
    private DigestDTO messageDigest;

    /**
     * Empty constructor
     */
    public SignMessageDigestExternalCmsDTO() {
        super();
    }

    /**
     * Default constructor
     *
     * @param messageDigest {@link DigestDTO} digest computed on prepared PDF signature revision
     * @param parameters {@link RemoteSignatureParameters} set of signature-driving parameters
     * @param signatureValue {@link SignatureValueDTO} contains result of a private-key encryption of a DTBS
     */
    public SignMessageDigestExternalCmsDTO(DigestDTO messageDigest, RemoteSignatureParameters parameters,
                                           SignatureValueDTO signatureValue) {
        super(parameters, signatureValue);
        this.messageDigest = messageDigest;
    }

    /**
     * Gets the message-digest
     *
     * @return {@link DigestDTO}
     */
    public DigestDTO getMessageDigest() {
        return messageDigest;
    }

    /**
     * Sets the message-digest
     *
     * @param messageDigest {@link DigestDTO}
     */
    public void setMessageDigest(DigestDTO messageDigest) {
        this.messageDigest = messageDigest;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SignMessageDigestExternalCmsDTO)) return false;
        if (!super.equals(o)) return false;
        SignMessageDigestExternalCmsDTO that = (SignMessageDigestExternalCmsDTO) o;
        return Objects.equals(messageDigest, that.messageDigest);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), messageDigest);
    }

    @Override
    public String toString() {
        return "SignMessageDigestExternalCMSDTO [messageDigest=" + messageDigest + ", parameters=" + getParameters() +
                ", signatureValue=" + getSignatureValue() + "]";
    }

}
