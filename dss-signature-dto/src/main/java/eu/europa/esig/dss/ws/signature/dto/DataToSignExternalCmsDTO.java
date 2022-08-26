package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Objects;

/**
 * Represents a DataTransferObject containing the required parameters for creation of DTBS (Data To Be Signed)
 * to be used for CMS for PAdES signature creation.
 * <p>
 * It's only possible to transfer an object by POST and REST.
 *
 */
public class DataToSignExternalCmsDTO extends AbstractDataToSignDTO {

    private static final long serialVersionUID = -442105442755635331L;

    /** Message-digest computed in PDF signature ByteRange */
    private DigestDTO messageDigest;

    /**
     * Empty constructor
     */
    public DataToSignExternalCmsDTO() {
        super();
    }

    /**
     * Default constructor
     *
     * @param messageDigest {@link DigestDTO} containing message-digest computed on PDF signature revision ByteRange
     * @param parameters {@link RemoteSignatureParameters} set of driven signature creation parameters
     */
    public DataToSignExternalCmsDTO(DigestDTO messageDigest, RemoteSignatureParameters parameters) {
        super(parameters);
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
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (messageDigest != null ? messageDigest.hashCode() : 0);
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DataToSignExternalCmsDTO)) return false;
        if (!super.equals(o)) return false;
        DataToSignExternalCmsDTO that = (DataToSignExternalCmsDTO) o;
        return Objects.equals(messageDigest, that.messageDigest);
    }

    @Override
    public String toString() {
        return "DataToSignExternalCMSDTO [messageDigest=" + messageDigest + ", parameters=" + getParameters() + "]";
    }

}
