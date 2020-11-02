package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.SelfIssuedOCSPCheck;

public class SelfIssuedOCSPCheckTest extends AbstractTestCheck {

	private static final String CERT_ID = "C-1";

	@Test
	public void revocationCertHashPresenceCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificate xmlCertificate = new XmlCertificate();
		xmlCertificate.setId(CERT_ID);

		XmlRevocation xmlRevocation = new XmlRevocation();
		XmlCertificate ocspResponderCertificate = new XmlCertificate();
		ocspResponderCertificate.setId("");

		XmlChainItem xmlChainItem = new XmlChainItem();
		xmlChainItem.setCertificate(ocspResponderCertificate);
		xmlRevocation.getCertificateChain().add(xmlChainItem);

		XmlRAC result = new XmlRAC();
		SelfIssuedOCSPCheck sioc = new SelfIssuedOCSPCheck(i18nProvider, result, new CertificateWrapper(xmlCertificate),
				new RevocationWrapper(xmlRevocation), constraint);
		sioc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failRevocationCertHashPresenceCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificate xmlCertificate = new XmlCertificate();
		xmlCertificate.setId(CERT_ID);

		XmlRevocation xmlRevocation = new XmlRevocation();
		XmlCertificate ocspResponderCertificate = new XmlCertificate();
		ocspResponderCertificate.setId(CERT_ID);

		XmlChainItem xmlChainItem = new XmlChainItem();
		xmlChainItem.setCertificate(ocspResponderCertificate);
		xmlRevocation.getCertificateChain().add(xmlChainItem);

		XmlRAC result = new XmlRAC();
		SelfIssuedOCSPCheck sioc = new SelfIssuedOCSPCheck(i18nProvider, result, new CertificateWrapper(xmlCertificate),
				new RevocationWrapper(xmlRevocation), constraint);
		sioc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
