package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ASiCEWithXAdESDuplicatedSigFileTest extends AbstractASiCWithXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/asic-xades-duplicated-sig-file.sce");
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        List<String> signatureIdList = diagnosticData.getSignatureIdList();
        for (String signatureId : signatureIdList) {
            SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
            if (diagnosticData.isBLevelTechnicallyValid(signatureId) && !signatureWrapper.isCounterSignature()) {
                List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
                assertEquals(3, Utils.collectionSize(retrievedOriginalDocuments));
                for (DSSDocument document : retrievedOriginalDocuments) {
                    assertNotNull(document);
                }
            }
        }
    }

}
