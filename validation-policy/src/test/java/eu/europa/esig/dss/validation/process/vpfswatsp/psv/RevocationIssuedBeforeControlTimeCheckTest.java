package eu.europa.esig.dss.validation.process.vpfswatsp.psv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.RevocationIssuedBeforeControlTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RevocationIssuedBeforeControlTimeCheckTest extends AbstractTestCheck {

    @Test
    public void validCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date controlTime = new Date();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setProductionDate(new Date(controlTime.getTime() - 86400000));  // 24 hours ago

        XmlVTS result = new XmlVTS();
        RevocationIssuedBeforeControlTimeCheck ribctc = new RevocationIssuedBeforeControlTimeCheck(i18nProvider, result,
                new RevocationWrapper(xmlRevocation), controlTime, constraint);
        ribctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date controlTime = new Date();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setProductionDate(new Date(controlTime.getTime() + 86400000));  // 24 hours after

        XmlVTS result = new XmlVTS();
        RevocationIssuedBeforeControlTimeCheck ribctc = new RevocationIssuedBeforeControlTimeCheck(i18nProvider, result,
                new RevocationWrapper(xmlRevocation), controlTime, constraint);
        ribctc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
