package eu.europa.esig.dss.validation.process.vpfltvd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.BestSignatureTimeNotBeforeCertificateIssuanceCheck;

public class BestSignatureTimeNotBeforeCertificateIssuenceCheckTest extends AbstractTestCheck {

	@Test
	public void validTest() throws Exception {
		
		Date bestSignatureTime = new Date();
		
		XmlCertificate xmlCertificate = new XmlCertificate();
		long nowMil = bestSignatureTime.getTime();
		xmlCertificate.setNotBefore(new Date(nowMil - 43200000)); // 12 hours ago

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		XmlPSV result = new XmlPSV();
		BestSignatureTimeNotBeforeCertificateIssuanceCheck<XmlPSV> bstnbcic = new BestSignatureTimeNotBeforeCertificateIssuanceCheck<XmlPSV>(
				i18nProvider, result, bestSignatureTime, new CertificateWrapper(xmlCertificate), constraint);
		bstnbcic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
		
		XmlConclusion conclusion = result.getConclusion();
		assertNull(conclusion);
		
	}

	@Test
	public void validWithCustomIndicationTest() throws Exception {
		
		Date bestSignatureTime = new Date();
		
		XmlCertificate xmlCertificate = new XmlCertificate();
		long nowMil = bestSignatureTime.getTime();
		xmlCertificate.setNotBefore(new Date(nowMil - 43200000)); // 12 hours ago

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		Indication currentIndication = Indication.INDETERMINATE;
		SubIndication currentSubIndication = SubIndication.OUT_OF_BOUNDS_NOT_REVOKED;
		
		XmlPSV result = new XmlPSV();
		BestSignatureTimeNotBeforeCertificateIssuanceCheck<XmlPSV> bstnbcic = new BestSignatureTimeNotBeforeCertificateIssuanceCheck<XmlPSV>(
				i18nProvider, result, bestSignatureTime, new CertificateWrapper(xmlCertificate), currentIndication, currentSubIndication, constraint);
		bstnbcic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
		
		XmlConclusion conclusion = result.getConclusion();
		assertNotNull(conclusion);
		assertEquals(currentIndication, conclusion.getIndication());
		assertEquals(currentSubIndication, conclusion.getSubIndication());
		
	}

	@Test
	public void invalidTest() throws Exception {
		
		Date bestSignatureTime = new Date();
		
		XmlCertificate xmlCertificate = new XmlCertificate();
		long nowMil = bestSignatureTime.getTime();
		xmlCertificate.setNotBefore(new Date(nowMil + 43200000)); // 12 hours after

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		
		Indication currentIndication = Indication.INDETERMINATE;
		SubIndication currentSubIndication = SubIndication.OUT_OF_BOUNDS_NOT_REVOKED;
		
		XmlPSV result = new XmlPSV();
		BestSignatureTimeNotBeforeCertificateIssuanceCheck<XmlPSV> bstnbcic = new BestSignatureTimeNotBeforeCertificateIssuanceCheck<XmlPSV>(
				i18nProvider, result, bestSignatureTime, new CertificateWrapper(xmlCertificate), currentIndication, currentSubIndication, constraint);
		bstnbcic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
		
		XmlConclusion conclusion = result.getConclusion();
		assertNotNull(conclusion);
		assertEquals(Indication.FAILED, conclusion.getIndication());
		assertEquals(SubIndication.NOT_YET_VALID, conclusion.getSubIndication());
		
	}
	
}
