package eu.europa.esig.dss.xades.requirements;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.xpath.XPathExpressionException;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESBaselineLTSigAndTstValDataTest extends XAdESBaselineTTest {

    @BeforeEach
    @Override
    void init() throws Exception {
        super.init();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setValidationDataEncapsulationStrategy(ValidationDataEncapsulationStrategy.CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA);
        return signatureParameters;
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

    /**
     * Checks UnsignedSignatureProperties present for T/LT/LTA levels
     */
    @Override
    protected void checkUnsignedProperties() throws XPathExpressionException {
        super.checkUnsignedProperties();

        assertTrue(checkCertificateValuesPresent());
        assertTrue(checkRevocationValuesPresent());
        assertFalse(checkTimeStampValidationDataPresent());
        assertFalse(checkAnyValidationDataPresent());
    }

}
