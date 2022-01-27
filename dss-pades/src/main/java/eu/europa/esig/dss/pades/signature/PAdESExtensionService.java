package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The service is used to obtain a validation data for signatures/timestamps within a PDF file and
 * incorporate it on the LT-level of the document (create a DSS dictionary revision)
 *
 */
public class PAdESExtensionService {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESExtensionService.class);

    /** Certificate verifier used to process the validation data */
    private final CertificateVerifier certificateVerifier;

    /** Pdf Object Factory to be used to PDF document processing */
    private final IPdfObjFactory pdfObjectFactory;

    /**
     * Constructor instantiating default {@code IPdfObjFactory}
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    public PAdESExtensionService(final CertificateVerifier certificateVerifier) {
        this(certificateVerifier, new ServiceLoaderPdfObjFactory());
    }

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param pdfObjectFactory {@link IPdfObjFactory}
     */
    public PAdESExtensionService(final CertificateVerifier certificateVerifier, final IPdfObjFactory pdfObjectFactory) {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier cannot be null!");
        Objects.requireNonNull(pdfObjectFactory, "PdfObjectFactory cannot be null!");
        this.certificateVerifier = certificateVerifier;
        this.pdfObjectFactory = pdfObjectFactory;
    }

    /**
     * This method adds a DSS dictionary revision to the given {@code document}
     * with the required validation data if needed
     *
     * NOTE: This method does not check the validity of the provided signatures/timestamps (e.g. a T-level, ...)
     *
     * @param document {@link DSSDocument} to extend
     * @return {@link DSSDocument} extended document
     */
    public DSSDocument incorporateValidationData(DSSDocument document) {
        return incorporateValidationData(document, null);
    }

    /**
     * This method adds a DSS dictionary revision to the given {@code document} protected by a {@code passwordProtection}
     * with the required validation data if needed.
     *
     * NOTE: This method does not check the validity of the provided signatures/timestamps (e.g. a T-level, ...)
     *
     * @param document {@link DSSDocument} to extend
     * @param passwordProtection {@link String} a password protection for the PDF document, when present
     * @return {@link DSSDocument} extended document
     */
    public DSSDocument incorporateValidationData(DSSDocument document, String passwordProtection) {
        Objects.requireNonNull(document, "The document to be extended shall be provided!");

        final PDFDocumentValidator pdfDocumentValidator = getPDFDocumentValidator(document, passwordProtection);

        final List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();
        final List<TimestampToken> detachedTimestamps = pdfDocumentValidator.getDetachedTimestamps();
        if (Utils.isCollectionNotEmpty(signatures)) {
            List<TimestampToken> signatureTimestamps = getSignatureTimestamps(signatures);
            if (Utils.isCollectionEmpty(signatureTimestamps)) {
                LOG.info("The found signatures within the document with name '{}' do not have a T-level. " +
                        "Validation data incorporation skipped.", document.getName());
                return document;
            }

        } else if (Utils.isCollectionNotEmpty(detachedTimestamps)) {
            // continue

        } else {
            LOG.info("No signatures or timestamps found within a document with name '{}'.", document.getName());
            return document;
        }

        PdfValidationDataContainer validationData = pdfDocumentValidator.getValidationData(signatures, detachedTimestamps);
        if (validationData.isEmpty()) {
            LOG.warn("No validation data has been obtained for the document with name '{}'. " +
                    "Return original document.", document.getName());
            return document;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding DSS dictionary revision to the document with name '{}'", document.getName());
        }
        final PDFSignatureService signatureService = newPdfSignatureService();
        return signatureService.addDssDictionary(document, validationData, passwordProtection);
    }

    private List<TimestampToken> getSignatureTimestamps(List<AdvancedSignature> signatures) {
        List<TimestampToken> signatureTimestamps = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            signatureTimestamps.addAll(signature.getAllTimestamps());
        }
        return signatureTimestamps;
    }

    private PDFDocumentValidator getPDFDocumentValidator(DSSDocument document, String passwordProtection) {
        PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
        pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
        pdfDocumentValidator.setPasswordProtection(passwordProtection);
        pdfDocumentValidator.setPdfObjFactory(pdfObjectFactory);
        return pdfDocumentValidator;
    }

    private PDFSignatureService newPdfSignatureService() {
        return pdfObjectFactory.newPAdESSignatureService();
    }

}
