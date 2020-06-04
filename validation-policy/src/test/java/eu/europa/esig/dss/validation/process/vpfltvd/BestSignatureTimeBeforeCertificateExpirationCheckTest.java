package eu.europa.esig.dss.validation.process.vpfltvd;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.BestSignatureTimeBeforeCertificateExpirationCheck;

public class BestSignatureTimeBeforeCertificateExpirationCheckTest extends AbstractTestCheck {

	@Test
	public void validTest() throws Exception {
		
		Date bestSignatureTime = new Date();
		
		XmlCertificate xmlCertificate = new XmlCertificate();
		long nowMil = bestSignatureTime.getTime();
		xmlCertificate.setNotAfter(new Date(nowMil + 43200000)); // 12 hours after

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlValidationProcessLongTermData result = new XmlValidationProcessLongTermData();
		BestSignatureTimeBeforeCertificateExpirationCheck bstbcec = new BestSignatureTimeBeforeCertificateExpirationCheck(
				i18nProvider, result, bestSignatureTime, new CertificateWrapper(xmlCertificate), constraint);
		bstbcec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
		
	}

	@Test
	public void invalidTest() throws Exception {
		
		Date bestSignatureTime = new Date();
		
		XmlCertificate xmlCertificate = new XmlCertificate();
		long nowMil = bestSignatureTime.getTime();
		xmlCertificate.setNotAfter(new Date(nowMil - 43200000)); // 12 hours ago

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlValidationProcessLongTermData result = new XmlValidationProcessLongTermData();
		BestSignatureTimeBeforeCertificateExpirationCheck bstbcec = new BestSignatureTimeBeforeCertificateExpirationCheck(
				i18nProvider, result, bestSignatureTime, new CertificateWrapper(xmlCertificate), constraint);
		bstbcec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
		
	}
	
}
