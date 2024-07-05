package eu.europa.esig.dss.validation.process.bbb.cv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataNameMatchCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ReferenceDataNameMatchCheckTest extends AbstractTestCheck {

    @Test
    void referenceDataIntactCheck() throws Exception {
        XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
        digestMatcher.setDataIntact(true);
        digestMatcher.setType(DigestMatcherType.MESSAGE_DIGEST);
        digestMatcher.setUri("sample.xml");
        digestMatcher.setDocumentName("sample.xml");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ReferenceDataNameMatchCheck<XmlCV> rdnmc = new ReferenceDataNameMatchCheck<>(i18nProvider, result, digestMatcher, constraint);
        rdnmc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void referenceDataNotIntactCheck() throws Exception {
        XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
        digestMatcher.setDataIntact(false);
        digestMatcher.setType(DigestMatcherType.MESSAGE_DIGEST);
        digestMatcher.setUri("sample.xml");
        digestMatcher.setDocumentName("sample.png");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ReferenceDataNameMatchCheck<XmlCV> rdnmc = new ReferenceDataNameMatchCheck<>(i18nProvider, result, digestMatcher, constraint);
        rdnmc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
