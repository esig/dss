package eu.europa.esig.dss.validation.process.bbb.cv;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataExistenceCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ReferenceDataExistenceCheckTest {

	@Test
	public void referenceDataExistenceCheck() throws Exception {
		XmlBasicSignature basicsig = new XmlBasicSignature();
		basicsig.setReferenceDataFound(true);

		XmlSignature sig = new XmlSignature();
		sig.setBasicSignature(basicsig);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ReferenceDataExistenceCheck rdec = new ReferenceDataExistenceCheck(result, new SignatureWrapper(sig),
				constraint);
		rdec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void referenceDataNotExistenceCheck() throws Exception {
		XmlBasicSignature basicsig = new XmlBasicSignature();
		basicsig.setReferenceDataFound(false);

		XmlSignature sig = new XmlSignature();
		sig.setBasicSignature(basicsig);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ReferenceDataExistenceCheck rdec = new ReferenceDataExistenceCheck(result, new SignatureWrapper(sig),
				constraint);
		rdec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
