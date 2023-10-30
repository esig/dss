package eu.europa.esig.dss.validation.process.vpftspwatsp.evidencerecord;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataGroupCheck;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ReferenceDataGroupCheckTest extends AbstractTestCheck {

    @Test
    public void validCheck() {
        XmlDigestMatcher oneDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);

        XmlDigestMatcher twoDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);

        List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
        digestMatchers.add(oneDigestMatcher);
        digestMatchers.add(twoDigestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ReferenceDataGroupCheck<XmlCV> rdgc = new ReferenceDataGroupCheck<>(i18nProvider, result, digestMatchers, constraint);
        rdgc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void oneInvalidRefCheck() {
        XmlDigestMatcher oneDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);

        XmlDigestMatcher twoDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);

        List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
        digestMatchers.add(oneDigestMatcher);
        digestMatchers.add(twoDigestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ReferenceDataGroupCheck<XmlCV> rdgc = new ReferenceDataGroupCheck<>(i18nProvider, result, digestMatchers, constraint);
        rdgc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void noneValidRefsCheck() {
        XmlDigestMatcher oneDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);

        XmlDigestMatcher twoDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);

        List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
        digestMatchers.add(oneDigestMatcher);
        digestMatchers.add(twoDigestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ReferenceDataGroupCheck<XmlCV> rdgc = new ReferenceDataGroupCheck<>(i18nProvider, result, digestMatchers, constraint);
        rdgc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
