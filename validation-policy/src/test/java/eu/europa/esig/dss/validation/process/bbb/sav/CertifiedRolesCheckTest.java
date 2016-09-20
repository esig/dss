package eu.europa.esig.dss.validation.process.bbb.sav;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertifiedRole;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CertifiedRolesCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class CertifiedRolesCheckTest {

	@Test
	public void certifiedRolesCheck() throws Exception {
		XmlCertifiedRole xcr = new XmlCertifiedRole();
		xcr.setCertifiedRole("Valid_Role");

		XmlSignature sig = new XmlSignature();
		sig.getCertifiedRoles().add(xcr);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Valid_Role");

		XmlSAV result = new XmlSAV();
		CertifiedRolesCheck crc = new CertifiedRolesCheck(result, new SignatureWrapper(sig), constraint);
		crc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void notCertifiedRolesCheck() throws Exception {
		XmlCertifiedRole xcr = new XmlCertifiedRole();
		xcr.setCertifiedRole("Invalid_Role");

		XmlSignature sig = new XmlSignature();
		sig.getCertifiedRoles().add(xcr);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Valid_Role");

		XmlSAV result = new XmlSAV();
		CertifiedRolesCheck crc = new CertifiedRolesCheck(result, new SignatureWrapper(sig), constraint);
		crc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
