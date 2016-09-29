package eu.europa.esig.dss.validation.process.bbb.vci;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyIdentifiedCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignaturePolicyIdentifiedCheckTest {

	@Test
	public void signaturePolicyIdentifiedCheck() throws Exception {
		XmlPolicy xmlPolicy = new XmlPolicy();
		xmlPolicy.setIdentified(true);

		XmlSignature sig = new XmlSignature();
		sig.setPolicy(xmlPolicy);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlVCI result = new XmlVCI();
		SignaturePolicyIdentifiedCheck spic = new SignaturePolicyIdentifiedCheck(result, new SignatureWrapper(sig),
				constraint);
		spic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void signaturePolicyNotIdentifiedCheck() throws Exception {
		XmlPolicy xmlPolicy = new XmlPolicy();
		xmlPolicy.setIdentified(false);

		XmlSignature sig = new XmlSignature();
		sig.setPolicy(xmlPolicy);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlVCI result = new XmlVCI();
		SignaturePolicyIdentifiedCheck spic = new SignaturePolicyIdentifiedCheck(result, new SignatureWrapper(sig),
				constraint);
		spic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
