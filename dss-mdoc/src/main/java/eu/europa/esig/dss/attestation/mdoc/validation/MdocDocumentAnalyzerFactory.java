package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentAnalyzer;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.analyzer.attestation.AttestationDocumentAnalyzerFactory;

/**
 * This class is used to parse and process attestations embedded
 * within an mdoc document structure as defined in ISO 18013-5.
 *
 */
public class MdocDocumentAnalyzerFactory implements AttestationDocumentAnalyzerFactory {

    /**
     * Default constructor
     */
    public MdocDocumentAnalyzerFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        MdocDeviceResponseDocumentAnalyzer mdocDeviceResponseAnalyzer = new MdocDeviceResponseDocumentAnalyzer();
        if (mdocDeviceResponseAnalyzer.isSupported(document)) {
            return true;
        }

        MdocIssuerSignedDocumentAnalyzer mdocIssuerSignedAnalyzer = new MdocIssuerSignedDocumentAnalyzer();
        if (mdocIssuerSignedAnalyzer.isSupported(document)) {
            return true;
        }

        return false;
    }

    @Override
    public DefaultAttestationDocumentAnalyzer create(DSSDocument document) {
        MdocDeviceResponseDocumentAnalyzer mdocDeviceResponseAnalyzer = new MdocDeviceResponseDocumentAnalyzer();
        if (mdocDeviceResponseAnalyzer.isSupported(document)) {
            return new MdocDeviceResponseDocumentAnalyzer(document);
        }

        MdocIssuerSignedDocumentAnalyzer mdocIssuerSignedAnalyzer = new MdocIssuerSignedDocumentAnalyzer();
        if (mdocIssuerSignedAnalyzer.isSupported(document)) {
            return new MdocIssuerSignedDocumentAnalyzer(document);
        }

        throw new IllegalArgumentException("Not supported document");
    }

}
