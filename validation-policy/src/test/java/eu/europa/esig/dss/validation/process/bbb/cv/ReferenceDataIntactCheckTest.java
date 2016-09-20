package eu.europa.esig.dss.validation.process.bbb.cv;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataIntactCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ReferenceDataIntactCheckTest {

	@Test
	public void referenceDataIntactCheck() throws Exception {
		XmlBasicSignature basicsig = new XmlBasicSignature();
		basicsig.setReferenceDataIntact(true);

		XmlSignature sig = new XmlSignature();
		sig.setBasicSignature(basicsig);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ReferenceDataIntactCheck rdic = new ReferenceDataIntactCheck(result, new SignatureWrapper(sig), constraint);
		rdic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void referenceDataNotIntactCheck() throws Exception {
		XmlBasicSignature basicsig = new XmlBasicSignature();
		basicsig.setReferenceDataIntact(false);

		XmlSignature sig = new XmlSignature();
		sig.setBasicSignature(basicsig);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ReferenceDataIntactCheck rdic = new ReferenceDataIntactCheck(result, new SignatureWrapper(sig), constraint);
		rdic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
