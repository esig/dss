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
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTimeStampCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ContentTimeStampCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlSignature sig = new XmlSignature();
        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setType(TimestampType.CONTENT_TIMESTAMP);
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        sig.setFoundTimestamps(List.of(xmlFoundTimestamp));

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ContentTimeStampCheck ctsc = new ContentTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        ctsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlSignature sig = new XmlSignature();
        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        sig.setFoundTimestamps(List.of(xmlFoundTimestamp));

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ContentTimeStampCheck ctsc = new ContentTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        ctsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void individualDataObjectsType() {
        XmlSignature sig = new XmlSignature();
        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setType(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        sig.setFoundTimestamps(List.of(xmlFoundTimestamp));

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ContentTimeStampCheck ctsc = new ContentTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        ctsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void allDataObjectsType() {
        XmlSignature sig = new XmlSignature();
        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setType(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        sig.setFoundTimestamps(List.of(xmlFoundTimestamp));

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ContentTimeStampCheck ctsc = new ContentTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        ctsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void multipleEntries() {
        XmlSignature sig = new XmlSignature();

        XmlFoundTimestamp xmlFoundTimestampOne = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestampOne = new XmlTimestamp();
        xmlTimestampOne.setType(TimestampType.CONTENT_TIMESTAMP);
        xmlFoundTimestampOne.setTimestamp(xmlTimestampOne);

        XmlFoundTimestamp xmlFoundTimestampTwo = new XmlFoundTimestamp();
        XmlTimestamp xmlTimestampTwo = new XmlTimestamp();
        xmlTimestampTwo.setType(TimestampType.SIGNATURE_TIMESTAMP);
        xmlFoundTimestampTwo.setTimestamp(xmlTimestampTwo);

        sig.setFoundTimestamps(List.of(xmlFoundTimestampOne, xmlFoundTimestampTwo));

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        ContentTimeStampCheck ctsc = new ContentTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        ctsc.execute();

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
        ContentTimeStampCheck ctsc = new ContentTimeStampCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
        ctsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
