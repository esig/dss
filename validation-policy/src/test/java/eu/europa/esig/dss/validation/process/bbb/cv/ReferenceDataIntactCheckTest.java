package eu.europa.esig.dss.validation.process.bbb.cv;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.validation.DigestMatcherType;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataIntactCheck;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ReferenceDataIntactCheckTest {

	@Test
	public void referenceDataIntactCheck() throws Exception {
		XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
		digestMatcher.setDataIntact(true);
		digestMatcher.setType(DigestMatcherType.MESSAGE_DIGEST);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ReferenceDataIntactCheck rdic = new ReferenceDataIntactCheck(result, digestMatcher, constraint);
		rdic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void referenceDataNotIntactCheck() throws Exception {
		XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
		digestMatcher.setDataIntact(false);
		digestMatcher.setType(DigestMatcherType.MESSAGE_DIGEST);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ReferenceDataIntactCheck rdic = new ReferenceDataIntactCheck(result, digestMatcher, constraint);
		rdic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
