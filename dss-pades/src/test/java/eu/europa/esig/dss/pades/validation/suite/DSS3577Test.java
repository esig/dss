package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.PdfLockAction;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS3577Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-3577.pdf"));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        PDFRevisionWrapper pdfRevision = signature.getPDFRevision();
        assertNotNull(pdfRevision);

        assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getSignatureFieldNames()));
        checkPdfSignatureDictionary(pdfRevision);

        assertFalse(Utils.isCollectionEmpty(signature.getPdfExtensionChanges()));
        assertFalse(Utils.isCollectionEmpty(signature.getPdfSignatureOrFormFillChanges()));
        assertTrue(Utils.isCollectionEmpty(signature.getPdfAnnotationChanges()));
        assertTrue(Utils.isCollectionEmpty(signature.getPdfUndefinedChanges()));

        XmlPDFLockDictionary sigFieldLock = signature.getSigFieldLock();
        assertNotNull(sigFieldLock);
        assertEquals(PdfLockAction.INCLUDE, sigFieldLock.getAction());
        assertEquals(1, sigFieldLock.getFields().size());
        assertEquals(signature.getFirstFieldName(), sigFieldLock.getFields().get(0));
        assertEquals(CertificationPermission.CHANGES_PERMITTED, sigFieldLock.getPermissions());
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()), MessageTag.BBB_FC_DSCNUOM_ANS));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()), MessageTag.BBB_FC_ISVASFLD_ANS));
    }

    private boolean checkMessageValuePresence(List<Message> messages, MessageTag messageTag) {
        return messages.stream().map(Message::getKey).collect(Collectors.toSet()).contains(messageTag.getId());
    }

}
