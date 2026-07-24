package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactWithKBSignatureNoCNFTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(this.getClass().getResourceAsStream("/validation/sdjwt-compact-kb-no-cnf.json"));
    }

    @Override
    protected void checkBLevelValid(final DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isKeyBindingSignature()) {
                assertFalse(signatureWrapper.isSignatureIntact());
                assertFalse(signatureWrapper.isSignatureValid());
                assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
            } else {
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());
                assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
            }
        }
    }

    @Override
    protected void verifySimpleReport(final SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        XmlSignature keyBindingSignature = simpleReport.getEAAKeyBindingSignature(simpleReport.getFirstEAAId());
        assertNotNull(keyBindingSignature);
        assertEquals(Indication.TOTAL_FAILED, keyBindingSignature.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, keyBindingSignature.getSubIndication());

        assertTrue(keyBindingSignature.getAdESValidationDetails().getError().stream().anyMatch(m -> MessageTag.BBB_CV_IRDOI_ANS.getId().equals(m.getKey())));
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (!signatureWrapper.isKeyBindingSignature()) {
                assertTrue(signatureWrapper.isSigningCertificateIdentified());
                assertTrue(signatureWrapper.isSigningCertificateReferencePresent());
                assertTrue(signatureWrapper.isSigningCertificateReferenceUnique());

                CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
                assertNotNull(signingCertificateReference);
                assertTrue(signingCertificateReference.isDigestValuePresent());
                assertTrue(signingCertificateReference.isDigestValueMatch());
                if (signingCertificateReference.isIssuerSerialPresent()) {
                    assertTrue(signingCertificateReference.isIssuerSerialMatch());
                }

                CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
                assertNotNull(signingCertificate);
                String signingCertificateId = signingCertificate.getId();
                String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
                String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
                assertEquals(signingCertificate.getCertificateDN(), certificateDN);
                assertEquals(signingCertificate.getSerialNumber(), certificateSerialNumber);

                assertTrue(Utils.isCollectionEmpty(signatureWrapper.foundCertificates()
                        .getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

            } else {
                assertNull(signatureWrapper.getSigningCertificate());
                assertNull(signatureWrapper.getSigningCertificatePublicKey());
            }

        }
    }

    @Override
    protected void checkDeviceKeyClaim(DiagnosticData diagnosticData) {
        for (AttestationWrapper eaa : diagnosticData.getEAAs()) {
            assertNull(eaa.getDevicePublicKey());
        }
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

    @Override
    protected void validateSignerInformation(SignerInformationType signerInformation) {
        // skip
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
