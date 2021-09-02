package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.UserFriendlyIdentifierProvider;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ASiCECAdESLevelLTAWithUserFriendlyIdentifiersTest extends ASiCECAdESLevelLTATest {

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setTokenIdentifierProvider(new UserFriendlyIdentifierProvider());
        return validator;
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        assertEquals(1, advancedSignatures.size());
        AdvancedSignature advancedSignature = advancedSignatures.get(0);
        SignatureWrapper signature = diagnosticData.getSignatureById(advancedSignature.getId());
        assertNull(signature);

        signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);
        assertTrue(signature.getId().contains("SIGNATURE"));
        assertTrue(signature.getId().contains(signature.getSigningCertificate().getCommonName()));
        assertTrue(signature.getId().contains(
                DSSUtils.formatDateWithCustomFormat(signature.getClaimedSigningTime(), "yyyyMMdd-HHmm")));

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getUsedCertificates()));
        for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
            assertTrue(certificateWrapper.getId().contains("CERTIFICATE"));
            assertTrue(certificateWrapper.getId().contains(certificateWrapper.getCommonName()));
            assertTrue(certificateWrapper.getId().contains(
                    DSSUtils.formatDateWithCustomFormat(certificateWrapper.getNotBefore(), "yyyyMMdd-HHmm")));
        }

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getAllRevocationData()));
        for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
            if (RevocationType.CRL.equals(revocationWrapper.getRevocationType())) {
                assertTrue(revocationWrapper.getId().contains("CRL"));
            } else if (RevocationType.OCSP.equals(revocationWrapper.getRevocationType())) {
                assertTrue(revocationWrapper.getId().contains("OCSP"));
            } else {
                fail("Unsupported Revocation type found : " + revocationWrapper.getRevocationType());
            }
            assertTrue(revocationWrapper.getId().contains(revocationWrapper.getSigningCertificate().getCommonName()));
            assertTrue(revocationWrapper.getId().contains(
                    DSSUtils.formatDateWithCustomFormat(revocationWrapper.getProductionDate(), "yyyyMMdd-HHmm")));
        }

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getTimestampList()));
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertTrue(timestampWrapper.getId().contains("TIMESTAMP"));
            assertTrue(timestampWrapper.getId().contains(timestampWrapper.getSigningCertificate().getCommonName()));
            assertTrue(timestampWrapper.getId().contains(
                    DSSUtils.formatDateWithCustomFormat(timestampWrapper.getProductionTime(), "yyyyMMdd-HHmm")));
        }

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getOriginalSignerDocuments()));
        for (SignerDataWrapper signerDataWrapper: diagnosticData.getOriginalSignerDocuments()) {
            assertTrue(signerDataWrapper.getId().contains("DOCUMENT"));
            assertTrue(signerDataWrapper.getId().contains(
                    DSSUtils.replaceAllNonAlphanumericCharacters(signerDataWrapper.getReferencedName(), "-")));
        }
    }

}
