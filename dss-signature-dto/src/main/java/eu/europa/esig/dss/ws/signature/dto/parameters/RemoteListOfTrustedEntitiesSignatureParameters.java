package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import java.io.Serializable;

/**
 * DTO used to define customizable parameters for a List of Trusted Entities signing
 * <p>
 * NOTE : other basic parameters are pre-configured for a List of Trusted Entities signing
 *
 */
public class RemoteListOfTrustedEntitiesSignatureParameters implements Serializable {

    private static final long serialVersionUID = -1595278455740096717L;

    /**
     * The signing certificate
     */
    private RemoteCertificate signingCertificate;

    /**
     * The encryption algorithm used for a signature creation by the current signing-certificate
     */
    private EncryptionAlgorithm encryptionAlgorithm;

    /**
     * The digest algorithm used to hash signed data on signing
     */
    private DigestAlgorithm digestAlgorithm;

    /**
     * The B-Level parameters
     */
    private RemoteBLevelParameters bLevelParameters = new RemoteBLevelParameters();

    /**
     * The Enveloped reference Id to be used
     */
    private String referenceId;

    /**
     * The DigestAlgorithm to be used for an Enveloped-signature reference
     */
    private DigestAlgorithm referenceDigestAlgorithm;

    /**
     * Default constructor instantiating object with null values
     */
    public RemoteListOfTrustedEntitiesSignatureParameters() {
        // empty
    }

    /**
     * Gets the signing certificate
     *
     * @return {@link RemoteCertificate}
     */
    public RemoteCertificate getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * Sets the signing certificate
     *
     * @param signingCertificate {@link RemoteCertificate}
     */
    public void setSigningCertificate(RemoteCertificate signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

    /**
     * Gets the encryption algorithm used by the signing-certificate
     *
     * @return {@link EncryptionAlgorithm}
     */
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Sets the encryption algorithm used by the signing-certificate
     *
     * @param encryptionAlgorithm {@link EncryptionAlgorithm}
     */
    public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    /**
     * Gets a digest algorithm used on signing
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Sets a digest algorithm used on signing
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Gets bLevel parameters
     *
     * @return {@link RemoteBLevelParameters}
     */
    public RemoteBLevelParameters getBLevelParameters() {
        return bLevelParameters;
    }

    /**
     * Sets bLevel parameters (e.g. claimed signing time, etc.)
     *
     * @param bLevelParameters {@link RemoteBLevelParameters}
     */
    public void setBLevelParameters(RemoteBLevelParameters bLevelParameters) {
        this.bLevelParameters = bLevelParameters;
    }

    /**
     * Gets an Id of an enveloped-signature reference
     *
     * @return {@link String}
     */
    public String getReferenceId() {
        return referenceId;
    }

    /**
     * Sets a custom if for an enveloped-reference creation (XML LoTE only).
     * <p>
     * NOTE: if not set, a default value will be used
     *
     * @param referenceId {@link String}
     */
    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    /**
     * Gets a {@code DigestAlgorithm} to be used on an enveloped-signature reference creation (XML LoTE only).
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getReferenceDigestAlgorithm() {
        return referenceDigestAlgorithm;
    }

    /**
     * Sets a {@code DigestAlgorithm} to be used on an enveloped-signature reference creation
     *
     * @param referenceDigestAlgorithm {@link DigestAlgorithm}
     */
    public void setReferenceDigestAlgorithm(DigestAlgorithm referenceDigestAlgorithm) {
        this.referenceDigestAlgorithm = referenceDigestAlgorithm;
    }

}
