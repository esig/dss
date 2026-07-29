package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class MdocAttestationPresentationNoDocumentsTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(Utils.fromBase64("o2d2ZXJzaW9uYzEuMG5kb2N1bWVudEVycm9yc4GhdW9yZy5pc28uMTgwMTMuNS4xLm1ETAFmc3RhdHVzAA=="));
    }

    @Override
    protected DSSDocument getSessionTranscript() {
        return null;
    }

    @Override
    protected int expectedSignaturesCount() {
        return 0;
    }

    @Override
    protected int expectedAttestationsCount() {
        return 0;
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertFalse(Utils.isCollectionNotEmpty(diagnosticData.getSignatures()));
        assertFalse(Utils.isCollectionNotEmpty(diagnosticData.getSignatureIdList()));
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        assertNotNull(signatureValidationStatus);
        assertNotNull(signatureValidationStatus.getMainIndication());
        assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication()); // TODO : improve ?
    }

    @Override
    protected void checkReportsSignatureIdentifier(Reports reports) {
        // skip
    }

}
