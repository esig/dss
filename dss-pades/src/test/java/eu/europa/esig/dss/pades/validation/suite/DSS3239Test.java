package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS3239Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-3226.pdf"));
    }

    @Test
    @Override
    public void validate() {
        DSSDocument signedDocument = getSignedDocument();

        SignedDocumentValidator documentValidator = getValidator(signedDocument);
        assertEquals(2, documentValidator.getSignatures().size());

        boolean originalSigFound = false;
        for (AdvancedSignature signature : documentValidator.getSignatures()) {
            List<DSSDocument> originalDocuments = documentValidator.getOriginalDocuments(signature);
            assertTrue(Utils.isCollectionNotEmpty(originalDocuments));
            for (DSSDocument originalDoc : originalDocuments) {
                Reports reports = verify(originalDoc);
                DiagnosticData diagnosticData = reports.getDiagnosticData();
                if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
                    originalSigFound = true;
                }
            }
        }
        assertTrue(originalSigFound);
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        // skip
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        // skip
    }

}
