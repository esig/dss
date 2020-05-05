package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationCertHashMatchCheck;

public class RevocationCertHashMatchCheckTest extends AbstractTestCheck {

	@Test
	public void revocationCertHashPresenceCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlRevocation xmlRevocation = new XmlRevocation();
		xmlRevocation.setCertHashExtensionMatch(true);
		
		XmlRAC result = new XmlRAC();
		RevocationCertHashMatchCheck rcmpc = new RevocationCertHashMatchCheck(i18nProvider, result, 
				new RevocationWrapper(xmlRevocation), constraint);
		rcmpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}
	
	@Test
	public void failRevocationCertHashPresenceCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlRevocation xmlRevocation = new XmlRevocation();
		xmlRevocation.setCertHashExtensionMatch(false);
		
		XmlRAC result = new XmlRAC();
		RevocationCertHashMatchCheck rcmpc = new RevocationCertHashMatchCheck(i18nProvider, result, 
				new RevocationWrapper(xmlRevocation), constraint);
		rcmpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
