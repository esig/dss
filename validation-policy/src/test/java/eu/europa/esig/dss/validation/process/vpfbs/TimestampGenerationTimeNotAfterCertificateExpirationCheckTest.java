package eu.europa.esig.dss.validation.process.vpfbs;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.TimestampGenerationTimeNotAfterCertificateExpirationCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TimestampGenerationTimeNotAfterCertificateExpirationCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {
        Date certNotAfter = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(certNotAfter);
        calendar.add(Calendar.MONTH, -1);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(calendar.getTime());

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessBasicSignature result = new XmlValidationProcessBasicSignature();
        TimestampGenerationTimeNotAfterCertificateExpirationCheck tgtnacec = new TimestampGenerationTimeNotAfterCertificateExpirationCheck<>(
                i18nProvider, result, new TimestampWrapper(xmlTimestamp), certNotAfter, constraint);
        tgtnacec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTest() throws Exception {
        Date certNotAfter = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(certNotAfter);
        calendar.add(Calendar.MONTH, 1);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(calendar.getTime());

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessBasicSignature result = new XmlValidationProcessBasicSignature();
        TimestampGenerationTimeNotAfterCertificateExpirationCheck tgtnacec = new TimestampGenerationTimeNotAfterCertificateExpirationCheck<>(
                i18nProvider, result, new TimestampWrapper(xmlTimestamp), certNotAfter, constraint);
        tgtnacec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
