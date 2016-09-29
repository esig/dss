package eu.europa.esig.dss.validation.process.bbb.sav;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureProductionPlace;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SignerLocationCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignerLocationCheckTest {

	@Test
	public void signerLocationCheckTest() throws Exception {
		XmlSignatureProductionPlace xspp = new XmlSignatureProductionPlace();

		XmlSignature sig = new XmlSignature();
		sig.setSignatureProductionPlace(xspp);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlSAV result = new XmlSAV();
		SignerLocationCheck slc = new SignerLocationCheck(result, new SignatureWrapper(sig), constraint);
		slc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedSignerLocationCheckTest() throws Exception {
		XmlSignature sig = new XmlSignature();

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlSAV result = new XmlSAV();
		SignerLocationCheck slc = new SignerLocationCheck(result, new SignatureWrapper(sig), constraint);
		slc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
