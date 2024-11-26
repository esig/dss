package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * Creates Signature parameters for a Trusted List V6 creation
 * <p>
 * NOTE: the same instance of SignatureParameters shall be used on calls
 * {@code DocumentSignatureService.getDataToSign(...)} and {@code DocumentSignatureService.signDocument(...)}
 *
 */
public class TrustedListV6SignatureParametersBuilder extends AbstractTrustedListSignatureParametersBuilder {

    /**
     * The constructor to build Signature Parameters for a Trusted List V6 signing with respect to ETSI TS 119 612.
     * NOTE: This class creates a new XAdES signature, according to ETSI EN 319 132-1
     *
     * @param signingCertificate {@link CertificateToken} to be used for a signature creation
     * @param tlXmlDocument      {@link DSSDocument} Trusted List XML document to be signed
     */
    public TrustedListV6SignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument tlXmlDocument) {
        super(signingCertificate, tlXmlDocument);
    }

    @Override
    public TrustedListV6SignatureParametersBuilder setReferenceId(String referenceId) {
        return (TrustedListV6SignatureParametersBuilder) super.setReferenceId(referenceId);
    }

    @Override
    public TrustedListV6SignatureParametersBuilder setReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        return (TrustedListV6SignatureParametersBuilder) super.setReferenceDigestAlgorithm(digestAlgorithm);
    }

    @Override
    public TrustedListV6SignatureParametersBuilder setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        return (TrustedListV6SignatureParametersBuilder) super.setDigestAlgorithm(digestAlgorithm);
    }

    @Override
    public TrustedListV6SignatureParametersBuilder setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        return (TrustedListV6SignatureParametersBuilder) super.setEncryptionAlgorithm(encryptionAlgorithm);
    }

    @Override
    public TrustedListV6SignatureParametersBuilder setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
        return (TrustedListV6SignatureParametersBuilder) super.setMaskGenerationFunction(maskGenerationFunction);
    }

    @Override
    public TrustedListV6SignatureParametersBuilder setBLevelParams(BLevelParameters bLevelParams) {
        return (TrustedListV6SignatureParametersBuilder) super.setBLevelParams(bLevelParams);
    }

    @Override
    protected boolean isEn319132() {
        return true;
    }

    @Override
    protected Integer getTargetTLVersion() {
        return 6;
    }

}
