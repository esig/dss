package eu.europa.esig.dss.validation.process.bbb.sav;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ClaimedRolesCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class ClaimedRolesCheckTest {

	@Test
	public void claimedRolesCheck() throws Exception {
		List<String> claimedRoles = new ArrayList<String>();
		claimedRoles.add("Claimed_Role");

		XmlSignature sig = new XmlSignature();
		sig.setClaimedRoles(claimedRoles);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Claimed_Role");

		XmlSAV result = new XmlSAV();
		ClaimedRolesCheck crc = new ClaimedRolesCheck(result, new SignatureWrapper(sig), constraint);
		crc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void notClaimedRolesCheck() throws Exception {
		List<String> claimedRoles = new ArrayList<String>();
		claimedRoles.add("Unclaimed_Role");

		XmlSignature sig = new XmlSignature();
		sig.setClaimedRoles(claimedRoles);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Claimed_Role");

		XmlSAV result = new XmlSAV();
		ClaimedRolesCheck crc = new ClaimedRolesCheck(result, new SignatureWrapper(sig), constraint);
		crc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
