package eu.europa.esig.dss.cbades.vical;

import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureParametersBuilder;
import eu.europa.esig.dss.spi.exception.IllegalInputException;

/**
 * Helper class to build signature parameters for signing
 * an ISO/IEC 18013-5 Verified issuer certificate authority list (VICAL) (see Annex C).
 * To create a pre-configured parameters, please call the {@link #build()} method.
 * Please note that the {@link #build()} method does not verify the validity of the submitted file's structure.
 *
 */
public class CborVICALSignatureParametersBuilder extends AbstractSignatureParametersBuilder<CBAdESSignatureParameters> {

    /**
     * The CBOR VICAL document
     */
    private final DSSDocument vicalDocument;

    /**
     * Default constructor.
     * When used, the {@link #assertConfigurationIsValid} is not supported.
     * Please use a constructor with a VICAL document provided if verification of the document conformity is required.
     *
     * @param signingCertificate {@link CertificateToken} representing a certificate associated with the signing key
     */
    public CborVICALSignatureParametersBuilder(CertificateToken signingCertificate) {
        this(signingCertificate, null);
    }

    /**
     * Constructor supporting verification of the VICAL document
     *
     * @param signingCertificate {@link CertificateToken} representing a certificate associated with the signing key
     * @param vicalDocument {@link DSSDocument} representing a document to be signed
     */
    public CborVICALSignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument vicalDocument) {
        super(signingCertificate);
        this.vicalDocument = vicalDocument;
    }

    @Override
    protected CBAdESSignatureParameters initParameters() {
        return new CBAdESSignatureParameters();
    }

    @Override
    public CBAdESSignatureParameters build() {
        final CBAdESSignatureParameters signatureParameters = super.build();

        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setTagged(false);
        signatureParameters.setIncludeKeyIdentifier(false);
        signatureParameters.setX5ChainHeaderPlacement(CBAdESSignatureParameters.X5ChainHeaderPlacement.unprotectedHeader);

        return signatureParameters;
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is applicable to the given document.
     * Thus, it verifies whether the provided document representing the CBOR VICAL is conformant to the definition
     * and the target version.
     *
     * @throws IllegalInputException if the provided CBOR VICAL has invalid structure
     * @throws DSSException is other error occurred during the processing
     */
    public void assertConfigurationIsValid() {
        // TODO : implement
        throw new UnsupportedOperationException("Not implemented.");
    }

}
