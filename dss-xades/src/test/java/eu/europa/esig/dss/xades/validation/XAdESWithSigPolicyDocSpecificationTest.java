package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XAdESWithSigPolicyDocSpecificationTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-sigPolicy-with-SPDocSpecification.xml");
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
        assertEquals("1.2.3.4.5.6", signature.getPolicyId());
        assertEquals("Test description", signature.getPolicyDescription());
        assertEquals(2, signature.getPolicyDocumentationReferences().size());
        assertEquals("http://spuri.test", signature.getPolicyUrl());
        assertEquals("1.2.3.4.5", signature.getPolicyDocSpecification());
    }

}
