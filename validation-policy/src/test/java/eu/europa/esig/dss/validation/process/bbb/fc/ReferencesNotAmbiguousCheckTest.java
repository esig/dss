package eu.europa.esig.dss.validation.process.bbb.fc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ReferencesNotAmbiguousCheck;

public class ReferencesNotAmbiguousCheckTest extends AbstractTestCheck {

	@Test
	public void valid() throws Exception {
		XmlSignature sig = new XmlSignature();

		XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
		xmlDigestMatcher.setType(DigestMatcherType.REFERENCE);
		xmlDigestMatcher.setDuplicated(false);

		sig.getDigestMatchers().add(xmlDigestMatcher);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		ReferencesNotAmbiguousCheck rnac = new ReferencesNotAmbiguousCheck(i18nProvider, result,
				new SignatureWrapper(sig), constraint);
		rnac.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void fail() throws Exception {
		XmlSignature sig = new XmlSignature();

		XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
		xmlDigestMatcher.setType(DigestMatcherType.REFERENCE);
		xmlDigestMatcher.setDuplicated(true);

		sig.getDigestMatchers().add(xmlDigestMatcher);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		ReferencesNotAmbiguousCheck rnac = new ReferencesNotAmbiguousCheck(i18nProvider, result,
				new SignatureWrapper(sig), constraint);
		rnac.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
