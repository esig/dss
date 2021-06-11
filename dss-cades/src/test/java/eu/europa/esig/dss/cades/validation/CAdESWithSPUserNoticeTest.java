package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CAdESWithSPUserNoticeTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/Signature-C-B-B-8.p7m");
    }

    @Override
    protected SignaturePolicyProvider getSignaturePolicyProvider() {
        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        signaturePolicyProvider.setDataLoader(new IgnoreDataLoader());
        return signaturePolicyProvider;
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals("1.2.3.4.5.1", signature.getPolicyId());
        assertEquals("../../Data/TARGET-SIGPOL-ETSI1.der", signature.getPolicyUrl());
        assertEquals("../../Data/TARGET-SIGPOL-ETSI1.der", signature.getPolicyNotice());
    }

}
