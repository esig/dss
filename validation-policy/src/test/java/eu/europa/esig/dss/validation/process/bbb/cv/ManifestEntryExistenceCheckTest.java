package eu.europa.esig.dss.validation.process.bbb.cv;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ManifestEntryExistenceCheck;

public class ManifestEntryExistenceCheckTest extends AbstractTestCheck {

	@Test
	public void valid() throws Exception {
		XmlDigestMatcher manifest = new XmlDigestMatcher();
		manifest.setType(DigestMatcherType.MANIFEST);
		
		XmlDigestMatcher entry1 = new XmlDigestMatcher();
		entry1.setType(DigestMatcherType.MANIFEST_ENTRY);
		
		XmlDigestMatcher entry2 = new XmlDigestMatcher();
		entry2.setType(DigestMatcherType.MANIFEST_ENTRY);
		
		List<XmlDigestMatcher> digestMatchers = Arrays.asList(manifest, entry1, entry2);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ManifestEntryExistenceCheck meec = new ManifestEntryExistenceCheck(i18nProvider, result, digestMatchers, constraint);
		meec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void invalid() throws Exception {
		XmlDigestMatcher manifest = new XmlDigestMatcher();
		manifest.setType(DigestMatcherType.MANIFEST);
		
		XmlDigestMatcher entry1 = new XmlDigestMatcher();
		entry1.setType(DigestMatcherType.OBJECT);
		
		XmlDigestMatcher entry2 = new XmlDigestMatcher();
		entry2.setType(DigestMatcherType.KEY_INFO);
		
		List<XmlDigestMatcher> digestMatchers = Arrays.asList(manifest, entry1, entry2);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ManifestEntryExistenceCheck meec = new ManifestEntryExistenceCheck(i18nProvider, result, digestMatchers, constraint);
		meec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
