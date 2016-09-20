package eu.europa.esig.dss.validation.process.bbb.vci;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyIdentifierCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class SignaturePolicyIdentifierCheckTest {

	@Test
	public void signaturePolicyIdentifiedCheck() throws Exception {
		XmlPolicy xmlPolicy = new XmlPolicy();
		xmlPolicy.setId("IMPLICIT_POLICY");

		XmlSignature sig = new XmlSignature();
		sig.setPolicy(xmlPolicy);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("IMPLICIT_POLICY");

		XmlVCI result = new XmlVCI();
		SignaturePolicyIdentifierCheck spic = new SignaturePolicyIdentifierCheck(result, new SignatureWrapper(sig),
				constraint);
		spic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void signaturePolicyNotIdentifierCheck() throws Exception {
		XmlPolicy xmlPolicy = new XmlPolicy();
		xmlPolicy.setId("INVALID_POLICY");

		XmlSignature sig = new XmlSignature();
		sig.setPolicy(xmlPolicy);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("IMPLICIT_POLICY");

		XmlVCI result = new XmlVCI();
		SignaturePolicyIdentifierCheck spic = new SignaturePolicyIdentifierCheck(result, new SignatureWrapper(sig),
				constraint);
		spic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
