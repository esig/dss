package eu.europa.esig.dss.xades.lote;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureParametersBuilder;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Helper class to build signature parameters for signing a TS 119 602 XML List of Trusted Entities.
 * To create a pre-configured parameters, please call the {@link #build()} method.
 * Please note that the {@link #build()} method does not verify the validity of the submitted file's structure.
 * To verify conformance of a LoTE to the specification, please call {@link #assertConfigurationIsValid()} method.
 *
 */
public class XmlListOfTrustedEntitiesSignatureParametersBuilder extends AbstractSignatureParametersBuilder<XAdESSignatureParameters> {

    /**
     * The default prefix for an enveloped signature reference id
     */
    private static final String DEFAULT_REFERENCE_PREFIX = "ref-enveloped-signature";

    /**
     * The XML List of Trusted Entities document
     */
    private final DSSDocument loteXmlDocument;

    /**
     * The Enveloped reference Id to use
     */
    private String referenceId;

    /**
     * The DigestAlgorithm to be used for an Enveloped reference
     */
    private DigestAlgorithm referenceDigestAlgorithm = DigestAlgorithm.SHA512;

    /**
     * Default constructor
     *
     * @param signingCertificate {@link CertificateToken} representing a certificate associated with the signing key
     * @param loteXmlDocument {@link DSSDocument} representing a document to be signed
     */
    public XmlListOfTrustedEntitiesSignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument loteXmlDocument) {
        super(signingCertificate);
        this.loteXmlDocument = loteXmlDocument;
    }

    /**
     * Sets an Enveloped Reference Id to use
     * <p>
     * Default: "ref-enveloped-signature"
     *
     * @param referenceId {@link String} reference Id
     * @return this builder
     */
    public XmlListOfTrustedEntitiesSignatureParametersBuilder setReferenceId(String referenceId) {
        this.referenceId = referenceId;
        return this;
    }

    /**
     * Sets an Enveloped Reference {@code DigestAlgorithm} to use
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used
     * @return this builder
     */
    public XmlListOfTrustedEntitiesSignatureParametersBuilder setReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.referenceDigestAlgorithm = digestAlgorithm;
        return this;
    }

    @Override
    protected XAdESSignatureParameters initParameters() {
        return new XAdESSignatureParameters();
    }

    @Override
    public XAdESSignatureParameters build() {
        assertDocumentProvided();

        final XAdESSignatureParameters signatureParameters = super.build();

        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setEn319132(true);
        signatureParameters.setSignedInfoCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);

        final List<DSSReference> references = getReferences();
        signatureParameters.setReferences(references);

        return signatureParameters;
    }

    /**
     * Returns a list of ds:References to be incorporated within the signature
     *
     * @return a list of {@link DSSReference}s
     */
    protected List<DSSReference> getReferences() {
        final List<DSSReference> references = new ArrayList<>();
        DSSReference envelopedSignatureReference = getEnvelopedSignatureReference();
        references.add(envelopedSignatureReference);
        return references;
    }

    /**
     * Creates the enveloped-signature ds:Reference
     *
     * @return {@link DSSReference}
     */
    protected DSSReference getEnvelopedSignatureReference() {
        DSSReference dssReference = new DSSReference();
        if (referenceId != null) {
            dssReference.setId(referenceId);
        } else {
            dssReference.setId(DEFAULT_REFERENCE_PREFIX);
        }
        dssReference.setUri("");
        dssReference.setContents(loteXmlDocument);
        dssReference.setDigestMethodAlgorithm(referenceDigestAlgorithm);

        final List<DSSTransform> transforms = new ArrayList<>();

        EnvelopedSignatureTransform signatureTransform = new EnvelopedSignatureTransform();
        transforms.add(signatureTransform);

        CanonicalizationTransform dssTransform = new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE);
        transforms.add(dssTransform);

        dssReference.setTransforms(transforms);
        return dssReference;
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is applicable to the given document.
     * Thus, it verifies whether the provided document representing the XML List of Trusted Entities is conformant to the definition
     * and the target version.
     * NOTE: this method requires 'specs-lote-xml module.
     *
     * @throws IllegalInputException if the provided XML List of Trusted Entities has invalid structure
     * @throws DSSException is other error occurred during the processing
     */
    public void assertConfigurationIsValid() throws IllegalInputException {
        assertDocumentProvided();

        List<String> errors;
        try {
            errors = XAdESListOfTrustedEntitiesUtils.validateUnsignedLOTE(loteXmlDocument);
        } catch (Exception e) {
            throw new DSSException(String.format("An error occurred on XML List of Trusted Entities validation : %s",
                    e.getMessage()), e);
        }
        if (Utils.isCollectionNotEmpty(errors)) {
            throw new IllegalInputException(String.format(
                    "XML List of Trusted Entities failed the validation : %s", Utils.joinStrings(errors, "; ")));
        }
    }

    /**
     * Verifies whether the XML LoTE document is provided.
     *
     * @throws NullPointerException if the XML LoTE document is not provided or null
     */
    protected void assertDocumentProvided() throws NullPointerException {
        Objects.requireNonNull(loteXmlDocument, "List of Trusted Entities document is not provided or null!");
    }

}
