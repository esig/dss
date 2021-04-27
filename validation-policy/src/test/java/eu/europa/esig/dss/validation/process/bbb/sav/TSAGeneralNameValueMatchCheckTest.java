package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTSAGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TSAGeneralNameValueMatchCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TSAGeneralNameValueMatchCheckTest extends AbstractTestCheck {

    @Test
    public void valid() throws Exception {
        XmlTimestamp timestamp = new XmlTimestamp();

        XmlTSAGeneralName xmlTSAGeneralName = new XmlTSAGeneralName();
        xmlTSAGeneralName.setValue("CN=Nowina Solutions");
        xmlTSAGeneralName.setContentMatch(true);
        xmlTSAGeneralName.setOrderMatch(true);
        timestamp.setTSAGeneralName(xmlTSAGeneralName);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        TSAGeneralNameValueMatchCheck tsavmc = new TSAGeneralNameValueMatchCheck(i18nProvider, result,
                new TimestampWrapper(timestamp), constraint);
        tsavmc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void orderDoNotMatch() throws Exception {
        XmlTimestamp timestamp = new XmlTimestamp();

        XmlTSAGeneralName xmlTSAGeneralName = new XmlTSAGeneralName();
        xmlTSAGeneralName.setValue("CN=Nowina Solutions");
        xmlTSAGeneralName.setContentMatch(true);
        xmlTSAGeneralName.setOrderMatch(false);
        timestamp.setTSAGeneralName(xmlTSAGeneralName);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        TSAGeneralNameValueMatchCheck tsavmc = new TSAGeneralNameValueMatchCheck(i18nProvider, result,
                new TimestampWrapper(timestamp), constraint);
        tsavmc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() throws Exception {
        XmlTimestamp timestamp = new XmlTimestamp();

        XmlTSAGeneralName xmlTSAGeneralName = new XmlTSAGeneralName();
        xmlTSAGeneralName.setValue("CN=Nowina Solutions");
        xmlTSAGeneralName.setContentMatch(false);
        xmlTSAGeneralName.setOrderMatch(false);
        timestamp.setTSAGeneralName(xmlTSAGeneralName);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSAV result = new XmlSAV();
        TSAGeneralNameValueMatchCheck tsavmc = new TSAGeneralNameValueMatchCheck(i18nProvider, result,
                new TimestampWrapper(timestamp), constraint);
        tsavmc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
