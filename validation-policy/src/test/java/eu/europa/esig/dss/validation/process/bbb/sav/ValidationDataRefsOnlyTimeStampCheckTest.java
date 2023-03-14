package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ValidationDataRefsOnlyTimeStampCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ValidationDataRefsOnlyTimeStampCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlSignature sig = new XmlSignature();
        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setType(TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        sig.setFoundTimestamps(Collections.singletonList(xmlFoundTimestamp));

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ValidationDataRefsOnlyTimeStampCheck vdrotsc = new ValidationDataRefsOnlyTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        vdrotsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlSignature sig = new XmlSignature();
        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setType(TimestampType.CONTENT_TIMESTAMP);
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        sig.setFoundTimestamps(Collections.singletonList(xmlFoundTimestamp));

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ValidationDataRefsOnlyTimeStampCheck vdrotsc = new ValidationDataRefsOnlyTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        vdrotsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void multipleEntries() {
        XmlSignature sig = new XmlSignature();

        XmlFoundTimestamp xmlFoundTimestampOne = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestampOne = new XmlTimestamp();
        xmlTimestampOne.setType(TimestampType.SIGNATURE_TIMESTAMP);
        xmlFoundTimestampOne.setTimestamp(xmlTimestampOne);

        XmlFoundTimestamp xmlFoundTimestampTwo = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestampTwo = new XmlTimestamp();
        xmlTimestampTwo.setType(TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
        xmlFoundTimestampTwo.setTimestamp(xmlTimestampTwo);

        sig.setFoundTimestamps(Arrays.asList(xmlFoundTimestampOne, xmlFoundTimestampTwo));

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ValidationDataRefsOnlyTimeStampCheck vdrotsc = new ValidationDataRefsOnlyTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        vdrotsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void empty() {
        XmlSignature sig = new XmlSignature();

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ValidationDataRefsOnlyTimeStampCheck vdrotsc = new ValidationDataRefsOnlyTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        vdrotsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
