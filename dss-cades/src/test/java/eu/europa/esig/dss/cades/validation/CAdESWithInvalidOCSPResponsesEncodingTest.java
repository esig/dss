package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CAdESWithInvalidOCSPResponsesEncodingTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESWithGeneralizedSigningTimeTest.class.getResourceAsStream("/validation/cades-invalid-ocsp-responses-encoding.p7s"));
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, Utils.fromBase64("wiaO5sDf+PLlr1A4msw2Z0yiFE+5DIPbMdGpwB3rlNo=")));
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(2, Utils.collectionSize(signature.foundRevocations()
                .getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.CMS_SIGNED_DATA)));
    }

}
