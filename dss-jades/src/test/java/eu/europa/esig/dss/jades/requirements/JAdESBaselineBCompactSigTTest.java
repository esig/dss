package eu.europa.esig.dss.jades.requirements;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESSigningTimeType;
import eu.europa.esig.dss.spi.DSSUtils;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class JAdESBaselineBCompactSigTTest extends JAdESBaselineBCompactTest {

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setJadesSigningTimeType(JAdESSigningTimeType.SIG_T);
        signatureParameters.bLevel().setSigningDate(DSSUtils.getUtcDate(2024, Calendar.JANUARY, 1)); // before 2025-05-15
        return signatureParameters;
    }

    @Override
    protected void checkSigningTime(Map<String, Object> protectedHeaderMap) throws Exception {
        Number iat = (Number) protectedHeaderMap.get("iat");
        assertNull(iat);

        String sigT = (String) protectedHeaderMap.get("sigT");
        assertNotNull(sigT);

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'"); // RFC 3339
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date date = sdf.parse(sigT);
        assertNotNull(date);
    }

}
