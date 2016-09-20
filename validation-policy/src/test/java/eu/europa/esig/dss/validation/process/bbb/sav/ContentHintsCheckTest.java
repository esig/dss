package eu.europa.esig.dss.validation.process.bbb.sav;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentHintsCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.ValueConstraint;

public class ContentHintsCheckTest {

	@Test
	public void contentHintsCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setContentHints("Valid_Value");

		ValueConstraint constraint = new ValueConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setValue("Valid_Value");

		XmlSAV result = new XmlSAV();
		ContentHintsCheck chc = new ContentHintsCheck(result, new SignatureWrapper(sig), constraint);
		chc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedContentHintsCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setContentHints("Invalid_Value");

		ValueConstraint constraint = new ValueConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setValue("Valid_Value");

		XmlSAV result = new XmlSAV();
		ContentHintsCheck chc = new ContentHintsCheck(result, new SignatureWrapper(sig), constraint);
		chc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
