package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationDataKnownCheck;

public class RevocationDataKnownCheckTest extends AbstractTestCheck {

	@Test
	public void revocationDataGoodStatusCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
		xmlCertificateRevocation.setRevocation(new XmlRevocation());
		xmlCertificateRevocation.setStatus(CertificateStatus.GOOD);
		
		XmlRAC result = new XmlRAC();
		RevocationDataKnownCheck rdkc = new RevocationDataKnownCheck(i18nProvider, result, 
				new CertificateRevocationWrapper(xmlCertificateRevocation), constraint);
		rdkc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void revocationDataRevokedCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
		xmlCertificateRevocation.setRevocation(new XmlRevocation());
		xmlCertificateRevocation.setStatus(CertificateStatus.REVOKED);
		
		XmlRAC result = new XmlRAC();
		RevocationDataKnownCheck rdkc = new RevocationDataKnownCheck(i18nProvider, result, 
				new CertificateRevocationWrapper(xmlCertificateRevocation), constraint);
		rdkc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void revocationDataUnknownCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
		xmlCertificateRevocation.setRevocation(new XmlRevocation());
		xmlCertificateRevocation.setStatus(CertificateStatus.UNKNOWN);
		
		XmlRAC result = new XmlRAC();
		RevocationDataKnownCheck rdkc = new RevocationDataKnownCheck(i18nProvider, result, 
				new CertificateRevocationWrapper(xmlCertificateRevocation), constraint);
		rdkc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
