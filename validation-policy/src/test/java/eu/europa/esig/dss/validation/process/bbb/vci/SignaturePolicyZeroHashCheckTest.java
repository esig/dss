package eu.europa.esig.dss.validation.process.bbb.vci;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyZeroHashCheck;

public class SignaturePolicyZeroHashCheckTest extends AbstractTestCheck {

	@Test
	public void signaturePolicyIdentifiedCheck() throws Exception {
		XmlPolicy xmlPolicy = new XmlPolicy();
		xmlPolicy.setZeroHash(true);

		XmlSignature sig = new XmlSignature();
		sig.setPolicy(xmlPolicy);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlVCI result = new XmlVCI();
		SignaturePolicyZeroHashCheck spzhc = new SignaturePolicyZeroHashCheck(i18nProvider, result, new SignatureWrapper(sig),
				constraint);
		spzhc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void signaturePolicyNotIdentifiedCheck() throws Exception {
		XmlPolicy xmlPolicy = new XmlPolicy();
		xmlPolicy.setZeroHash(false);

		XmlSignature sig = new XmlSignature();
		sig.setPolicy(xmlPolicy);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlVCI result = new XmlVCI();
		SignaturePolicyZeroHashCheck spzhc = new SignaturePolicyZeroHashCheck(i18nProvider, result, new SignatureWrapper(sig),
				constraint);
		spzhc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
