package eu.europa.esig.dss.attestation.sd.jwt.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEAA;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

class SDJWTJsonSerializationAttestationBrokenSignatureTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(this.getClass().getResourceAsStream("/validation/sdjwt-json-broken-signature.json"));
    }

    @Override
    protected void checkBLevelValid(final DiagnosticData diagnosticData) {
        assertEquals(1, diagnosticData.getSignatures().size());
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertFalse(signatureWrapper.isSignatureIntact());
            assertFalse(signatureWrapper.isSignatureValid());
            assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
        }
    }

    @Override
    protected void verifySimpleReport(final SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        XmlEAA eaa = simpleReport.getEAAById(simpleReport.getFirstEAAId());
        assertEquals(Indication.FAILED, eaa.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, eaa.getSubIndication());

        assertTrue(eaa.getEAASignature().get(0).getAdESValidationDetails().getError().stream().anyMatch(m -> MessageTag.BBB_CV_IRDOI_ANS.getId().equals(m.getKey())));
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
