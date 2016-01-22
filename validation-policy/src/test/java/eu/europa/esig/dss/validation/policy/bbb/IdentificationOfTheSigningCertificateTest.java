package eu.europa.esig.dss.validation.policy.bbb;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.validation.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.isc.IdentificationOfTheSigningCertificate;
import eu.europa.esig.dss.validation.wrappers.DiagnosticData;

public class IdentificationOfTheSigningCertificateTest extends AbstractValidationPolicy {

	private static final Logger logger = LoggerFactory.getLogger(IdentificationOfTheSigningCertificateTest.class);

	@Test
	public void testWithBasicData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		IdentificationOfTheSigningCertificate verification = new IdentificationOfTheSigningCertificate(diagnosticData, diagnosticData.getSignatures().get(0),
				Context.SIGNATURE, getPolicy());
		XmlISC isc = verification.execute();

		for (XmlConstraint constraint : isc.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.VALID, isc.getConclusion().getIndication());
		Assert.assertEquals(6, isc.getConstraint().size());
	}

	@Test
	public void testWithDigestNotPresent() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithDigestValueOfTheCertificateNotPresent();

		IdentificationOfTheSigningCertificate verification = new IdentificationOfTheSigningCertificate(diagnosticData, diagnosticData.getSignatures().get(0),
				Context.SIGNATURE, getPolicy());
		XmlISC isc = verification.execute();

		for (XmlConstraint constraint : isc.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, isc.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, isc.getConclusion().getSubIndication());
		Assert.assertEquals(4, isc.getConstraint().size());
	}

	@Test
	public void testWithDigestNotMatch() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithDigestValueOfTheCertificateNotMatch();

		IdentificationOfTheSigningCertificate verification = new IdentificationOfTheSigningCertificate(diagnosticData, diagnosticData.getSignatures().get(0),
				Context.SIGNATURE, getPolicy());
		XmlISC isc = verification.execute();

		for (XmlConstraint constraint : isc.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, isc.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, isc.getConclusion().getSubIndication());
		Assert.assertEquals(5, isc.getConstraint().size());
	}

	// @Test
	public void testWithIssuerSerialNotMatch() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithIssuerSerialOfTheCertificateNotMatch();

		IdentificationOfTheSigningCertificate verification = new IdentificationOfTheSigningCertificate(diagnosticData, diagnosticData.getSignatures().get(0),
				Context.SIGNATURE, getPolicy());
		XmlISC isc = verification.execute();

		for (XmlConstraint constraint : isc.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, isc.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, isc.getConclusion().getSubIndication());
		Assert.assertEquals(6, isc.getConstraint().size());
	}

	@Test
	public void testWithNullSigningCertificate() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataSigningCertificateNotFound();

		IdentificationOfTheSigningCertificate verification = new IdentificationOfTheSigningCertificate(diagnosticData, diagnosticData.getSignatures().get(0),
				Context.SIGNATURE, getPolicy());
		XmlISC isc = verification.execute();

		for (XmlConstraint constraint : isc.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, isc.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, isc.getConclusion().getSubIndication());
		Assert.assertEquals(3, isc.getConstraint().size());
	}

	@Test
	public void testWithNoSigningCertificateFound() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataSigningCertificateNotPresent();

		IdentificationOfTheSigningCertificate verification = new IdentificationOfTheSigningCertificate(diagnosticData, diagnosticData.getSignatures().get(0),
				Context.SIGNATURE, getPolicy());
		XmlISC isc = verification.execute();

		for (XmlConstraint constraint : isc.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, isc.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, isc.getConclusion().getSubIndication());
		Assert.assertEquals(1, isc.getConstraint().size());
	}
}
