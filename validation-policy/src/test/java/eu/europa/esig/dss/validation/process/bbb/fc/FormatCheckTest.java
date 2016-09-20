package eu.europa.esig.dss.validation.process.bbb.fc;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FormatCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class FormatCheckTest {

	@Test
	public void validFormat() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat("CAdES_BASELINE_B");

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("CAdES_BASELINE_B");

		XmlFC result = new XmlFC();
		FormatCheck fc = new FormatCheck(result, new SignatureWrapper(sig), constraint);
		fc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void invalidFormat() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat("Invalid_format");

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("CAdES_BASELINE_B");

		XmlFC result = new XmlFC();
		FormatCheck fc = new FormatCheck(result, new SignatureWrapper(sig), constraint);
		fc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
