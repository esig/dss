package eu.europa.esig.dss.jades.requirements;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.ValidationDataContainerType;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESBaselineLTSerialiazationAnyValDataTest extends AbstractJAdESSerializationSignatureRequirementsCheck {

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
        signatureParameters.setValidationDataContainerType(ValidationDataContainerType.ANY_VALIDATION_DATA_ONLY);
        return signatureParameters;
    }

    @Override
    protected void checkArchiveTimestamp(Map<?, ?> unprotectedHeaderMap) {
        List<?> arcTst = (List<?>) getEtsiUElement(unprotectedHeaderMap, "arcTst");
        assertNull(arcTst);
    }

    @Override
    protected void checkCertificateValues(Map<?, ?> unprotectedHeaderMap) {
        List<?> xVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "xVals");
        assertNull(xVals);
    }

    @Override
    protected void checkRevocationValues(Map<?, ?> unprotectedHeaderMap) {
        Map<?, ?> rVals = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "rVals");
        assertNull(rVals);
    }

    @Override
    protected void checkTstValidationData(Map<?, ?> unprotectedHeaderMap) {
        Map<?, ?> tstVD = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "tstVD");
        assertNull(tstVD);
    }

    @Override
    protected void checkAnyValidationData(Map<?, ?> unprotectedHeaderMap) {
        super.checkAnyValidationData(unprotectedHeaderMap);

        Map<?, ?> anyVD = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "anyValData");
        List<?> xVals = (List<?>) anyVD.get("xVals");
        assertTrue(Utils.isCollectionNotEmpty(xVals));

        Map<?, ?> rVals = (Map<?, ?>) anyVD.get("rVals");
        assertTrue(Utils.isMapNotEmpty(rVals));
    }

}
