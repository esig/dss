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
import eu.europa.esig.dss.simplereport.jaxb.XmlAttestation;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

class SDJWTCompactInvalidSignatureTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(this.getClass().getResourceAsStream("/validation/sdjwt-compact-invalid-signature.json"));
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

        XmlAttestation attestation = simpleReport.getAttestationById(simpleReport.getFirstAttestationId());
        assertEquals(Indication.FAILED, attestation.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, attestation.getSubIndication());

        assertTrue(attestation.getAttestationSignature().get(0).getAdESValidationDetails().getError().stream().anyMatch(m -> MessageTag.BBB_CV_IRDOI_ANS.getId().equals(m.getKey())));
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
