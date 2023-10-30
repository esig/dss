package eu.europa.esig.dss.validation.process.vpftspwatsp.evidencerecord;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.AtLeastOneReferenceDataObjectFoundCheck;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AtLeastOneReferenceDataObjectFoundCheckTest extends AbstractTestCheck {

    @Test
    public void oneRefCheck() {
        XmlDigestMatcher oneDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setDataFound(true);

        XmlDigestMatcher twoDigestMatcher = new XmlDigestMatcher();
        twoDigestMatcher.setDataFound(false);

        List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
        digestMatchers.add(oneDigestMatcher);
        digestMatchers.add(twoDigestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        AtLeastOneReferenceDataObjectFoundCheck<XmlCV> alordofc =
                new AtLeastOneReferenceDataObjectFoundCheck<>(i18nProvider, result, digestMatchers, constraint);
        alordofc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void multipleRefsCheck() {
        XmlDigestMatcher oneDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setDataFound(true);

        XmlDigestMatcher twoDigestMatcher = new XmlDigestMatcher();
        twoDigestMatcher.setDataFound(true);

        List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
        digestMatchers.add(oneDigestMatcher);
        digestMatchers.add(twoDigestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        AtLeastOneReferenceDataObjectFoundCheck<XmlCV> alordofc =
                new AtLeastOneReferenceDataObjectFoundCheck<>(i18nProvider, result, digestMatchers, constraint);
        alordofc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void noneRefsCheck() {
        XmlDigestMatcher oneDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setDataFound(false);

        XmlDigestMatcher twoDigestMatcher = new XmlDigestMatcher();
        twoDigestMatcher.setDataFound(false);

        List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
        digestMatchers.add(oneDigestMatcher);
        digestMatchers.add(twoDigestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        AtLeastOneReferenceDataObjectFoundCheck<XmlCV> alordofc =
                new AtLeastOneReferenceDataObjectFoundCheck<>(i18nProvider, result, digestMatchers, constraint);
        alordofc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void emptyListCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        AtLeastOneReferenceDataObjectFoundCheck<XmlCV> alordofc =
                new AtLeastOneReferenceDataObjectFoundCheck<>(i18nProvider, result, Collections.emptyList(), constraint);
        alordofc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
