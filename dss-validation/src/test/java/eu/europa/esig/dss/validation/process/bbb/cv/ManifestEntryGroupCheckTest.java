package eu.europa.esig.dss.validation.process.bbb.cv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ManifestEntryGroupCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ManifestEntryGroupCheckTest extends AbstractTestCheck {

    @Test
    void valid() throws Exception {
        XmlDigestMatcher manifest = new XmlDigestMatcher();
        manifest.setType(DigestMatcherType.MANIFEST);
        manifest.setDataFound(true);

        XmlDigestMatcher entry1 = new XmlDigestMatcher();
        entry1.setType(DigestMatcherType.MANIFEST_ENTRY);
        entry1.setDataFound(true);

        XmlDigestMatcher entry2 = new XmlDigestMatcher();
        entry2.setType(DigestMatcherType.MANIFEST_ENTRY);
        entry2.setDataFound(true);

        List<XmlDigestMatcher> digestMatchers = Arrays.asList(manifest, entry1, entry2);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ManifestEntryGroupCheck megc = new ManifestEntryGroupCheck(i18nProvider, result, digestMatchers, constraint);
        megc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() throws Exception {
        XmlDigestMatcher manifest = new XmlDigestMatcher();
        manifest.setType(DigestMatcherType.MANIFEST);
        manifest.setDataFound(true);

        XmlDigestMatcher entry1 = new XmlDigestMatcher();
        entry1.setType(DigestMatcherType.MANIFEST_ENTRY);
        entry1.setDataFound(true);

        XmlDigestMatcher entry2 = new XmlDigestMatcher();
        entry2.setType(DigestMatcherType.MANIFEST_ENTRY);
        entry2.setDataFound(false);

        List<XmlDigestMatcher> digestMatchers = Arrays.asList(manifest, entry1, entry2);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ManifestEntryGroupCheck megc = new ManifestEntryGroupCheck(i18nProvider, result, digestMatchers, constraint);
        megc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void otherDocs() throws Exception {
        XmlDigestMatcher manifest = new XmlDigestMatcher();
        manifest.setType(DigestMatcherType.MANIFEST);
        manifest.setDataFound(true);

        XmlDigestMatcher entry1 = new XmlDigestMatcher();
        entry1.setType(DigestMatcherType.OBJECT);
        entry1.setDataFound(true);

        XmlDigestMatcher entry2 = new XmlDigestMatcher();
        entry2.setType(DigestMatcherType.KEY_INFO);
        entry2.setDataFound(false);

        List<XmlDigestMatcher> digestMatchers = Arrays.asList(manifest, entry1, entry2);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ManifestEntryGroupCheck megc = new ManifestEntryGroupCheck(i18nProvider, result, digestMatchers, constraint);
        megc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
