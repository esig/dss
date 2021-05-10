package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2451Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-byterange-overlap.pdf"));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean failedSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isBLevelTechnicallyValid()) {
                validSigFound = true;
            } else {
                failedSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(failedSigFound);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        boolean validSigFound = false;
        boolean failedSigFound = false;
        for (String signatureId : simpleReport.getSignatureIdList()) {
            if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(signatureId))) {
                assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(signatureId));
                failedSigFound = true;
            } else {
                validSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(failedSigFound);
    }

}
