package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.FileNameBuilder;
import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CAdESUnsignedAttributes;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.CMSForPAdESBaselineRequirementsChecker;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.DSSMessageDigest;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Collections;
import java.util.Objects;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;

/**
 * This service contains methods for a PAdES signature creation using an external CMS provider.
 * <p>
 * To create a signature with the current class, please follow the algorithm:
 * 1) Create a message-digest computed on PDF ByteRange:
 *    {@code Digest messageDigest = getMessageDigest(DSSDocument toSignDocument, PAdESSignatureParameters parameters)};
 * 2) Create CMS signature signing the message-digest (e.g. using a remote-signing solution):
 *    {@code DSSDocument cmsDocument = *create CMS using message-digest*};
 * 3) OPTIONAL : verify validity of the obtained CMS signature using the methods:
 *    - {@code isValidCMSSignedData(Digest messageDigest, DSSDocument cms)} -
 *            to check cryptographical validity of the signature;
 *    - {@code isValidPAdESBaselineCMSSignedData(Digest messageDigest, DSSDocument cms)} -
 *            to check CMS applicability rules for a PAdES signature creation;
 * 4) Create PAdES signature by incorporating obtained CMS signature to a PDF document:
 *    {@code DSSDocument signedDocument =
 *            signDocument(DSSDocument toSignDocument, PAdESSignatureParameters parameters, DSSDocument cmsDocument)}.
 * <p>
 * NOTES:
 * - Unlike configuration in {@code PAdESService} an instance of {@code PAdESSignatureParameters} in this class
 *   does not need to have signingCertificate and certificateChain defined when using external signing.
 * - Signature extension to -T level with the current class will never lead to a signature-timestamp
 *   incorporated within CMS Signed Data. It always creates a new revision with a document timestamp.
 * - Content timestamp is not supported by this service.
 *
 */
public class PAdESWithExternalCMSService implements Serializable {

    private static final long serialVersionUID = -6168823023670905054L;

    private static final Logger LOG = LoggerFactory.getLogger(PAdESWithExternalCMSService.class);

    /** The CertificateVerifier used for a certificate chain validation */
    private CertificateVerifier certificateVerifier;

    /** The TSPSource to use for timestamp requests */
    private TSPSource tspSource;

    /** Loads a relevant implementation for signature creation/extension */
    private IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();

    /**
     * Default constructor to instantiate PAdESExternalCMSSignatureService
     */
    public PAdESWithExternalCMSService() {
        // empty
    }

    /**
     * This setter allows to define the CertificateVerifier.
     * Used for signature extension and on CMS creation method.
     * Not required for B-level remote-signing solutions.
     *
     * @param certificateVerifier
     *            {@link CertificateVerifier} used to verify the certificate chain
     */
    public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    /**
     * This setter allows to define the TSP (timestamp provider) source.
     *
     * @param tspSource
     *            The time stamp source which is used when timestamping the signature.
     */
    public void setTspSource(TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    /**
     * Set the IPdfObjFactory. Allow to set the used implementation. Cannot be null.
     *
     * @param pdfObjFactory
     *                      the implementation to be used.
     */
    public void setPdfObjFactory(IPdfObjFactory pdfObjFactory) {
        Objects.requireNonNull(pdfObjFactory, "PdfObjFactory is null");
        this.pdfObjFactory = pdfObjFactory;
    }

    /**
     * This method computes message-digest of the signature ByteRange to be used for CMS Signed Data creation
     *
     * @param toSignDocument {@link DSSDocument}
     *                                       represented by a PDF document to be signed
     * @param parameters {@link PAdESSignatureParameters}
     *                                       for signature configuration
     * @return {@link DSSMessageDigest}
     *                                       of the PDF signature ByteRange to be signed
     */
    public DSSMessageDigest getMessageDigest(DSSDocument toSignDocument, PAdESSignatureParameters parameters) {
        Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
        assertDocumentValid(toSignDocument);

        final PDFSignatureService pdfSignatureService = getPAdESSignatureService();
        return pdfSignatureService.messageDigest(toSignDocument, parameters);
    }

    /**
     * This method embeds the provided external {@code cmsDocument}
     * to a {code toSignDocument} within a new signature revision.
     *
     * @param toSignDocument {@link DSSDocument}
     *                                       represented by a PDF document to be signed
     * @param parameters {@link PAdESSignatureParameters}
     *                                       for signature configuration
     * @param cmsDocument {@link DSSDocument}
     *                                       representing an external CMS Signed Data
     *                                       (e.g. {@code CMSSignedDocument} or {@code InMemoryDocument})
     * @return {@link DSSDocument} representing a signed PDF document
     */
    public DSSDocument signDocument(DSSDocument toSignDocument, PAdESSignatureParameters parameters,
                                    DSSDocument cmsDocument) {
        Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
        Objects.requireNonNull(parameters.getSignatureLevel(), "SignatureLevel shall be defined within parameters!");
        Objects.requireNonNull(cmsDocument, "CMSDocument cannot be null!");
        assertDocumentValid(toSignDocument);
        assertDocumentValid(cmsDocument);

        final CMSSignedData cmsSignedData = toCMSSignedData(cmsDocument);
        byte[] derEncodedCMS = DSSASN1Utils.getDEREncoded(cmsSignedData);

        final PDFSignatureService pdfSignatureService = getPAdESSignatureService();
        DSSDocument signatureDocument = pdfSignatureService.sign(toSignDocument, derEncodedCMS, parameters);

        if (SignatureLevel.PAdES_BASELINE_B != parameters.getSignatureLevel() && isExtensionRequired(cmsSignedData, parameters)) {
            parameters.getContext().setDetachedContents(Collections.singletonList(toSignDocument));
            PAdESService padesService = getPAdESService();
            signatureDocument = padesService.extendDocument(signatureDocument, parameters);
        }

        signatureDocument.setName(getFinalDocumentName(toSignDocument, parameters.getSignatureLevel()));
        parameters.reinit();
        return signatureDocument;
    }

    private CMSSignedData toCMSSignedData(DSSDocument document) {
        try {
            return DSSUtils.toCMSSignedData(document);
        } catch (Exception e) {
            throw new IllegalInputException(String.format("A CMS file is expected : %s", e.getMessage()), e);
        }
    }

    /**
     * This method is used to return a new {@code PDFSignatureService} for a signature creation
     *
     * @return {@link PDFSignatureService}
     */
    protected PDFSignatureService getPAdESSignatureService() {
        return pdfObjFactory.newPAdESSignatureService();
    }

    /**
     * This method creates an instance of a {@code PAdESService} to be used for signature extension
     *
     * @return {@link PAdESService}
     */
    protected PAdESService getPAdESService() {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier shall be provided for PAdES extension!");
        Objects.requireNonNull(tspSource, "TSPSource shall be provided for PAdES extension!");

        PAdESService padesService = new PAdESService(certificateVerifier);
        padesService.setTspSource(tspSource);
        padesService.setPdfObjFactory(pdfObjFactory);
        return padesService;
    }

    /**
     * Generates and returns a final name for the document to be created
     *
     * @param originalFile {@link DSSDocument} original signed/extended document
     * @param level {@link SignatureLevel} the final signature level
     * @return {@link String} the document filename
     */
    protected String getFinalDocumentName(DSSDocument originalFile, SignatureLevel level) {
        return new FileNameBuilder().setOriginalFilename(originalFile.getName())
                .setSigningOperation(SigningOperation.SIGN).setSignatureLevel(level)
                .setSignaturePackaging(SignaturePackaging.ENVELOPED).setMimeType(MimeType.PDF).build();
    }

    private void assertDocumentValid(DSSDocument document) {
        if (document instanceof DigestDocument) {
            throw new IllegalArgumentException("DigestDocument cannot be used for PAdES!");
        }
    }

    private boolean isExtensionRequired(CMSSignedData cmsSignedData, PAdESSignatureParameters parameters) {
        if (SignatureLevel.PAdES_BASELINE_T.equals(parameters.getSignatureLevel())) {
            // only first SignerInformation is considered.
            SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();
            CAdESUnsignedAttributes unsignedAttributes = CAdESUnsignedAttributes.build(signerInformation);
            for (CAdESAttribute attribute : unsignedAttributes.getAttributes()) {
                if (id_aa_signatureTimeStampToken.equals(attribute.getASN1Oid())) {
                    LOG.info("The CMS signature already contains a signature-time-stamp attribute! " +
                            "The extension to '%s' level is skipped.");
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * This method verifies if the {@code cms} is cryptographically valid
     *
     * @param messageDigest {@link Digest} computed on PDF's signature ByteRange
     * @param cms {@link DSSDocument} representing an external CMSSignedData
     * @return TRUE if the given CMSSignedData is valid, FALSE otherwise
     */
    public boolean isValidCMSSignedData(Digest messageDigest, DSSDocument cms) {
        Objects.requireNonNull(messageDigest, "messageDigest shall be provided!");
        Objects.requireNonNull(cms, "CMSSignedDocument shall be provided!");

        CMSSignedData cmsSignedData;
        try {
            cmsSignedData = DSSUtils.toCMSSignedData(cms);
        } catch (Exception e) {
            LOG.error("Unable to decode the provided CMS document : {}", e.getMessage());
            return false;
        }

        SignerInformationStore signerInfos = cmsSignedData.getSignerInfos();
        if (signerInfos.size() != 1) {
            LOG.error("CMSSignedData shall contain one and only one SignerInformation for signature signing process!");
            return false;
        }

        final CAdESSignature cadesSignature = toCAdESSignature(cmsSignedData, messageDigest);
        SignatureCryptographicVerification scv = cadesSignature.getSignatureCryptographicVerification();
        if (!scv.isSignatureValid()) {
            LOG.error("CMSSignedData signature is not valid!");
            return false;
        }
        return true;
    }

    /**
     * This method verifies if the given {@code cms} signature is compliant for PAdES format
     *
     * @param messageDigest {@link Digest} computed on PDF's signature ByteRange
     * @param cms {@link DSSDocument} to be verified
     * @return TRUE if the CMS is compliant to PAdES specification, FALSE otherwise
     */
    public boolean isValidPAdESBaselineCMSSignedData(Digest messageDigest, DSSDocument cms) {
        Objects.requireNonNull(messageDigest, "messageDigest shall be provided!");
        Objects.requireNonNull(cms, "CMSSignedDocument shall be provided!");

        CMSSignedData cmsSignedData;
        try {
            cmsSignedData = DSSUtils.toCMSSignedData(cms);
        } catch (Exception e) {
            LOG.error("Unable to decode the provided CMS document : {}", e.getMessage());
            return false;
        }

        final CAdESSignature cadeSSignature = toCAdESSignature(cmsSignedData, messageDigest);
        final CMSForPAdESBaselineRequirementsChecker cmsRequirementsChecker =
                new CMSForPAdESBaselineRequirementsChecker(cadeSSignature);
        return cmsRequirementsChecker.isValidForPAdESBaselineBProfile();
    }

    private CAdESSignature toCAdESSignature(CMSSignedData cmsSignedData, Digest messageDigest) {
        CAdESSignature signature = new CAdESSignature(cmsSignedData, cmsSignedData.getSignerInfos().iterator().next());
        signature.setDetachedContents(Collections.singletonList(DSSUtils.toDigestDocument(messageDigest)));
        return signature;
    }

}
