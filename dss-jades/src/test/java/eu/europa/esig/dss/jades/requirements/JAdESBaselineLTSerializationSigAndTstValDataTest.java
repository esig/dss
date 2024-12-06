package eu.europa.esig.dss.jades.requirements;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESBaselineLTSerializationSigAndTstValDataTest extends AbstractJAdESSerializationSignatureRequirementsCheck {

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
        signatureParameters.setValidationDataEncapsulationStrategy(ValidationDataEncapsulationStrategy.CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA);
        return signatureParameters;
    }

    @Override
    protected void checkArchiveTimestamp(Map<?, ?> unprotectedHeaderMap) {
        List<?> arcTst = (List<?>) getEtsiUElement(unprotectedHeaderMap, "arcTst");
        assertNull(arcTst);
    }

    @Override
    protected void checkTstValidationData(Map<?, ?> unprotectedHeaderMap) {
        Map<?, ?> tstVD = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "tstVD");
        assertNull(tstVD);
    }

    @Override
    protected void checkAnyValidationData(Map<?, ?> unprotectedHeaderMap) {
        Map<?, ?> anyVD = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "anyValData");
        assertNull(anyVD);
    }

    @Override
    protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
        // All data shall be embedded together with this strategy
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<RelatedCertificateWrapper> certificateValues = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES);
            if (Utils.isCollectionNotEmpty(certificateValues)) {
                List<String> signatureCertificateIds = populateWithRevocationCertificatesRecursively(new ArrayList<>(), signature.getCertificateChain());
                for (TimestampWrapper timestamp : signature.getTimestampList()) {
                    populateWithRevocationCertificatesRecursively(signatureCertificateIds, timestamp.getCertificateChain());
                }
                for (SignatureWrapper counterSignature : diagnosticData.getAllCounterSignaturesForMasterSignature(signature)) {
                    populateWithRevocationCertificatesRecursively(signatureCertificateIds, counterSignature.getCertificateChain());
                    for (TimestampWrapper timestamp : counterSignature.getTimestampList()) {
                        populateWithRevocationCertificatesRecursively(signatureCertificateIds, timestamp.getCertificateChain());
                    }
                }
                for (CertificateWrapper certificate : certificateValues) {
                    assertTrue(signatureCertificateIds.contains(certificate.getId()));
                }
            }
            List<RelatedCertificateWrapper> tstValidationData = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
            assertTrue(Utils.isCollectionEmpty(tstValidationData));
            List<RelatedCertificateWrapper> anyValidationData = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA);
            assertTrue(Utils.isCollectionEmpty(anyValidationData));
        }
    }

}
