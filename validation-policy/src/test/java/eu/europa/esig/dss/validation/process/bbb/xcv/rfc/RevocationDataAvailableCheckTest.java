package eu.europa.esig.dss.validation.process.bbb.xcv.rfc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataAvailableCheck;

public class RevocationDataAvailableCheckTest extends AbstractTestCheck {

	@Test
	public void revocationDataAvailableCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlCertificate xmlCertificate = new XmlCertificate();
		xmlCertificate.getRevocations().add(new XmlCertificateRevocation());

		XmlRFC result = new XmlRFC();
		RevocationDataAvailableCheck<XmlRFC> rdac = new RevocationDataAvailableCheck<XmlRFC>(i18nProvider, result, 
				new CertificateWrapper(xmlCertificate), constraint);
		rdac.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedRevocationDataAvailableCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlCertificate xmlCertificate = new XmlCertificate();

		XmlRFC result = new XmlRFC();
		RevocationDataAvailableCheck<XmlRFC> rdac = new RevocationDataAvailableCheck<XmlRFC>(i18nProvider, result, 
				new CertificateWrapper(xmlCertificate), constraint);
		rdac.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
