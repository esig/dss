package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlArchiveTimestampHashIndex;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.CAdESV3HashIndexCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CAdESV3HashIndexCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
        xmlTimestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        XmlArchiveTimestampHashIndex xmlArchiveTimestampHashIndex = new XmlArchiveTimestampHashIndex();
        xmlArchiveTimestampHashIndex.setValid(true);
        xmlTimestamp.setArchiveTimestampHashIndex(xmlArchiveTimestampHashIndex);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), constraint);
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
        xmlTimestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        XmlArchiveTimestampHashIndex xmlArchiveTimestampHashIndex = new XmlArchiveTimestampHashIndex();
        xmlArchiveTimestampHashIndex.setValid(false);
        xmlTimestamp.setArchiveTimestampHashIndex(xmlArchiveTimestampHashIndex);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), constraint);
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noAtsHashIndex() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
        xmlTimestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), constraint);
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void cadesV2Tst() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
        xmlTimestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_V2);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), constraint);
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sigTstTst() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), constraint);
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
