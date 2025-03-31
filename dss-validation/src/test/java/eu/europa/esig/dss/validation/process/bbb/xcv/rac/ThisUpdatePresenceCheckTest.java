package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.ThisUpdatePresenceCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ThisUpdatePresenceCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(new Date());

        XmlRAC result = new XmlRAC();
        ThisUpdatePresenceCheck tupc = new ThisUpdatePresenceCheck(i18nProvider, result,
                new RevocationWrapper(xmlRevocation), constraint);
        tupc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(null);

        XmlRAC result = new XmlRAC();
        ThisUpdatePresenceCheck tupc = new ThisUpdatePresenceCheck(i18nProvider, result,
                new RevocationWrapper(xmlRevocation), constraint);
        tupc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
