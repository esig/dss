package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.spi.validation.executor.SkipValidationContextExecutor;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLTASkipValidationContextExecutorTest extends XAdESLTATest {

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator documentValidator = super.getValidator(signedDocument);
        documentValidator.setValidationContextExecutor(SkipValidationContextExecutor.INSTANCE);
        return documentValidator;
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateReferences()));
        assertEquals(1, Utils.collectionSize(diagnosticData.getAllOrphanRevocationObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        // skip
    }

}
