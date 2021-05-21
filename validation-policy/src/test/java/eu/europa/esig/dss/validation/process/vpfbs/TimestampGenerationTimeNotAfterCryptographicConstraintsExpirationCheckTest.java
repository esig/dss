package eu.europa.esig.dss.validation.process.vpfbs;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {
        Date cryptoNotAfter = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(cryptoNotAfter);
        calendar.add(Calendar.MONTH, -1);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(calendar.getTime());

        XmlCryptographicValidation xmlCryptographicValidation = new XmlCryptographicValidation();
        xmlCryptographicValidation.setNotAfter(cryptoNotAfter);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessBasicSignature result = new XmlValidationProcessBasicSignature();
        TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheck tgtnaccec =
                new TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheck<>(
                        i18nProvider, result, new TimestampWrapper(xmlTimestamp), xmlCryptographicValidation, constraint);
        tgtnaccec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTest() throws Exception {
        Date cryptoNotAfter = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(cryptoNotAfter);
        calendar.add(Calendar.MONTH, 1);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(calendar.getTime());

        XmlCryptographicValidation xmlCryptographicValidation = new XmlCryptographicValidation();
        xmlCryptographicValidation.setNotAfter(cryptoNotAfter);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessBasicSignature result = new XmlValidationProcessBasicSignature();
        TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheck tgtnaccec =
                new TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheck<>(
                        i18nProvider, result, new TimestampWrapper(xmlTimestamp), xmlCryptographicValidation, constraint);
        tgtnaccec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
