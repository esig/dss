package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DSS2821ExtensionToTLevelTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-2821.pdf"));

        PAdESService service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getSelfSignedTsa());

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        return service.extendDocument(dssDocument, parameters);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.PAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}
