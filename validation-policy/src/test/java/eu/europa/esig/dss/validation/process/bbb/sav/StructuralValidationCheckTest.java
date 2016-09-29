package eu.europa.esig.dss.validation.process.bbb.sav;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlStructuralValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.StructuralValidationCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class StructuralValidationCheckTest {

	@Test
	public void structuralValidationCheck() throws Exception {
		XmlStructuralValidation xsv = new XmlStructuralValidation();
		xsv.setValid(true);

		XmlSignature sig = new XmlSignature();
		sig.setStructuralValidation(xsv);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlSAV result = new XmlSAV();
		StructuralValidationCheck svc = new StructuralValidationCheck(result, new SignatureWrapper(sig), constraint);
		svc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedStructuralValidationCheck() throws Exception {
		XmlStructuralValidation xsv = new XmlStructuralValidation();
		xsv.setValid(false);

		XmlSignature sig = new XmlSignature();
		sig.setStructuralValidation(xsv);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlSAV result = new XmlSAV();
		StructuralValidationCheck svc = new StructuralValidationCheck(result, new SignatureWrapper(sig), constraint);
		svc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void emptyStructuralValidationCheck() throws Exception {
		XmlSignature sig = new XmlSignature();

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlSAV result = new XmlSAV();
		StructuralValidationCheck svc = new StructuralValidationCheck(result, new SignatureWrapper(sig), constraint);
		svc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
