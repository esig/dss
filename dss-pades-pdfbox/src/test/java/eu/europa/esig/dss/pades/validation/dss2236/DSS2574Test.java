package eu.europa.esig.dss.pades.validation.dss2236;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class DSS2574Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/muestra-firmado-firmado.pdf"));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        super.checkPdfRevision(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertFalse(signatureWrapper.arePdfModificationsDetected());
        }
    }

}
