package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import java.io.Serializable;

/**
 * DTO used to define customizable parameters for a Trusted List signing
 *
 * NOTE : other basic parameters are pre-configured for a Trusted List signing
 *
 */
public class RemoteTrustedListSignatureParameters implements Serializable {

    private static final long serialVersionUID = 5459292709179313722L;

    /**
     * The signing certificate
     */
    private RemoteCertificate signingCertificate;

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
     * Sets a custom if for an enveloped-reference creation
     *
     * NOTE: if not set, a default value will be used
     *
     * @param referenceId {@link String}
     */
    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    /**
     * Gets a {@code DigestAlgorithm} to be used on an enveloped-signature reference creation
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
