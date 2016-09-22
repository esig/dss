package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationFreshnessCheckerResult;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationFreshnessCheckerResultTest {

	@Test
	public void revocationFreshnessCheckerResult() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlConclusion xc = new XmlConclusion();
		xc.setIndication(Indication.PASSED);

		XmlRFC resultRFC = new XmlRFC();
		resultRFC.setConclusion(xc);

		XmlSubXCV result = new XmlSubXCV();
		RevocationFreshnessCheckerResult rfc = new RevocationFreshnessCheckerResult(result, resultRFC, constraint);
		rfc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedRevocationFreshnessCheckerResult() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlConclusion xc = new XmlConclusion();
		xc.setIndication(Indication.FAILED);

		XmlRFC resultRFC = new XmlRFC();
		resultRFC.setConclusion(xc);

		XmlSubXCV result = new XmlSubXCV();
		RevocationFreshnessCheckerResult rfc = new RevocationFreshnessCheckerResult(result, resultRFC, constraint);
		rfc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
