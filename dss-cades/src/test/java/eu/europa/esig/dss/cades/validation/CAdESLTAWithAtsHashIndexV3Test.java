package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CAdESLTAWithAtsHashIndexV3Test extends PKIFactoryAccess {

    @Test
    public void test() {
        DSSDocument doc = new FileDocument("src/test/resources/validation/cades-lta-ats-hash-index-v3.pkcs7");
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports report = validator.validateDocument();
        DiagnosticData diagnosticData = report.getDiagnosticData();

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(2, signature.getTimestampList().size());

        for (TimestampWrapper timestampWrapper : signature.getTimestampList()) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureValid());
        }

    }

    @Override
    protected String getSigningAlias() {
        return null;
    }

}
