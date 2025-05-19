package eu.europa.esig.dss.xades.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.validation.SignatureValidationAlerter;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.definition.xadesen.XAdESEvidencerecordNamespaceElement;
import eu.europa.esig.dss.xades.signature.ExtensionBuilder;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentAnalyzer;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Objects;

/**
 * This class is used to embed an existing evidence record to a XAdES signature
 *
 */
public class EmbeddedEvidenceRecordBuilder extends ExtensionBuilder {

    /**
     * The CertificateVerifier to be used for timestamps validation
     */
    private final CertificateVerifier certificateVerifier;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier} providing configuration for evidence record validation
     */
    public EmbeddedEvidenceRecordBuilder(final CertificateVerifier certificateVerifier) {
        this.certificateVerifier = new CertificateVerifierBuilder(certificateVerifier).buildOfflineCopy();
    }

    /**
     * Adds the evidence record document to a signature with the given {@code signatureId},
     * provided the evidence record correctly applies to the signature
     *
     * @param signatureDocument {@link DSSDocument} where the evidence record will be added
     * @param evidenceRecordDocument {@link DSSDocument} to add
     * @param parameters {@link XAdESEvidenceRecordIncorporationParameters} to be used for the process configuration
     * @return {@link DSSDocument} with a signature containing the evidence record as an unsigned property
     */
    public DSSDocument addEvidenceRecord(DSSDocument signatureDocument, DSSDocument evidenceRecordDocument,
                                         XAdESEvidenceRecordIncorporationParameters parameters) {
        Objects.requireNonNull(signatureDocument, "Signature document must be provided!");
        Objects.requireNonNull(evidenceRecordDocument, "Evidence record document must be provided!");
        Objects.requireNonNull(parameters, "XAdESEvidenceRecordIncorporationParameters must be provided!");

        final XMLDocumentAnalyzer documentAnalyzer = initDocumentAnalyzer(signatureDocument, parameters.getDetachedContents());

        XAdESSignature signature = getXAdESSignature(documentAnalyzer, parameters.getSignatureId());
        return addEvidenceRecord(signature, evidenceRecordDocument, parameters);
    }

    /**
     * Gets a signature to incorporate evidence record into
     *
     * @param documentAnalyzer {@link DefaultDocumentAnalyzer}
     * @param signatureId {@link String} identifier of a signature to return
     * @return {@link XAdESSignature}
     */
    protected XAdESSignature getXAdESSignature(DefaultDocumentAnalyzer documentAnalyzer, String signatureId) {
        if (signatureId != null) {
            AdvancedSignature signature = documentAnalyzer.getSignatureById(signatureId);
            if (signature == null) {
                throw new IllegalArgumentException(String.format("Unable to find a signature with Id : %s!", signatureId));
            }
            return (XAdESSignature) signature;

        } else {
            List<AdvancedSignature> signatures = documentAnalyzer.getSignatures();
            if (Utils.isCollectionEmpty(signatures)) {
                throw new IllegalInputException(String.format("No signatures found in the document with name '%s'",
                        documentAnalyzer.getDocument().getName()));
            } else if (Utils.collectionSize(signatures) > 1) {
                throw new IllegalArgumentException(String.format("More than one signature found in a document with name '%s'! " +
                                "Please provide a signatureId within the parameters.", documentAnalyzer.getDocument().getName()));
            }
            // if one signature
            return (XAdESSignature) signatures.get(0);
        }
    }

    /**
     * This method adds {@code evidenceRecordDocument} to a {@code documentDom}
     *
     * @param xadesSignature {@link XAdESSignature} signature to add {@link SignaturePolicyStore}
     * @param evidenceRecordDocument {@link DSSDocument} to be added
     * @param parameters {@link XAdESEvidenceRecordIncorporationParameters}
     */
    protected DSSDocument addEvidenceRecord(XAdESSignature xadesSignature, DSSDocument evidenceRecordDocument,
                                            XAdESEvidenceRecordIncorporationParameters parameters) {
        xadesSignature = initializeSignatureBuilder(xadesSignature);

        ensureUnsignedProperties();
        ensureUnsignedSignatureProperties();

        EvidenceRecord evidenceRecord = getEvidenceRecord(evidenceRecordDocument, xadesSignature, parameters.getDetachedContents());
        assertEvidenceRecordValid(evidenceRecord, parameters);

        Element sealingEvidenceRecordElement = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom,
                parameters.getXadesERNamespace(), XAdESEvidencerecordNamespaceElement.SEALING_EVIDENCE_RECORDS);

        switch (evidenceRecord.getEvidenceRecordType()) {
            case XML_EVIDENCE_RECORD:
                Document erDom = DomUtils.buildDOM(evidenceRecordDocument);
                DomUtils.adoptChildren(sealingEvidenceRecordElement, erDom);
                break;
            case ASN1_EVIDENCE_RECORD:
                String base64EncodedER = Utils.toBase64(evidenceRecord.getEncoded());
                DomUtils.addTextElement(documentDom, sealingEvidenceRecordElement, parameters.getXadesERNamespace(),
                        XAdESEvidencerecordNamespaceElement.ASN1_EVIDENCE_RECORD, base64EncodedER);
                break;
            default:
                throw new UnsupportedOperationException(String.format("The Evidence Record type '%s' is not supported!",
                        evidenceRecord.getEvidenceRecordType()));
        }

        return createXmlDocument();
    }

    private EvidenceRecord getEvidenceRecord(DSSDocument evidenceRecordDocument, XAdESSignature signature, List<DSSDocument> detachedContents) {
        try {
            EvidenceRecordAnalyzer evidenceRecordAnalyzer = EvidenceRecordAnalyzerFactory.fromDocument(evidenceRecordDocument);

            final XAdESEmbeddedEvidenceRecordHelper embeddedEvidenceRecordHelper = new XAdESEmbeddedEvidenceRecordHelper(signature);
            embeddedEvidenceRecordHelper.setDetachedContents(detachedContents);
            evidenceRecordAnalyzer.setEmbeddedEvidenceRecordHelper(embeddedEvidenceRecordHelper);

            return evidenceRecordAnalyzer.getEvidenceRecord();

        } catch (Exception e) {
            throw new IllegalInputException(String.format(
                    "Unable to build an evidence record from the provided document. Reason : %s", e.getMessage()), e);
        }
    }

    private void assertEvidenceRecordValid(EvidenceRecord evidenceRecord, XAdESEvidenceRecordIncorporationParameters parameters) {
        for (ReferenceValidation referenceValidation : evidenceRecord.getReferenceValidation()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType() && !referenceValidation.isIntact()) {
                if (Utils.isCollectionEmpty(parameters.getDetachedContents())) {
                    throw new IllegalInputException("The digest covered by the evidence record do not correspond to " +
                            "the digest computed on the signature and/or detached content! " +
                            "In case of detached signature, please use #setDetachedContent method to provide original documents.");
                } else {
                    throw new IllegalInputException("The digest covered by the evidence record do not correspond to " +
                            "the digest computed on the signature and/or detached content!");
                }
            }
        }
        validateTimestamps(evidenceRecord);
    }

    private void validateTimestamps(EvidenceRecord evidenceRecord) {
        SignatureValidationContext validationContext = new SignatureValidationContext();
        validationContext.initialize(certificateVerifier);

        validationContext.addDocumentCertificateSource(evidenceRecord.getCertificateSource());
        for (TimestampToken timestampToken : evidenceRecord.getTimestamps()) {
            validationContext.addTimestampTokenForVerification(timestampToken);
        }

        validationContext.validate();

        SignatureValidationAlerter signatureValidationAlerter = new SignatureValidationAlerter(validationContext);
        signatureValidationAlerter.assertAllTimestampsValid();
    }

    private XMLDocumentAnalyzer initDocumentAnalyzer(DSSDocument signatureDocument, List<DSSDocument> detachedContents) {
        XMLDocumentAnalyzer analyzer = initDocumentAnalyzer(signatureDocument);
        analyzer.setDetachedContents(detachedContents);
        return analyzer;
    }

}
