package eu.europa.esig.dss.validation.process.bbb.cv;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.SignatureIntactCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignatureIntactCheckTest {

	@Test
	public void signatureIntactCheck() throws Exception {
		XmlBasicSignature basicsig = new XmlBasicSignature();
		basicsig.setSignatureIntact(true);

		XmlSignature sig = new XmlSignature();
		sig.setBasicSignature(basicsig);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		SignatureIntactCheck sic = new SignatureIntactCheck(result, new SignatureWrapper(sig), constraint);
		sic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void signatureNotIntactCheck() throws Exception {
		XmlBasicSignature basicsig = new XmlBasicSignature();
		basicsig.setSignatureIntact(false);

		XmlSignature sig = new XmlSignature();
		sig.setBasicSignature(basicsig);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		SignatureIntactCheck sic = new SignatureIntactCheck(result, new SignatureWrapper(sig), constraint);
		sic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
