package eu.europa.esig.dss.validation.policy.bbb;

import java.util.Calendar;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.bbb.util.TestPolicyGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.xcv.X509CertificateValidation;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class X509CertificateValidationTest {

	private static final Logger logger = LoggerFactory.getLogger(X509CertificateValidationTest.class);

	@Test
	public void CertificateValidationWithBasicData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(),
				Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.VALID, xcv.getConclusion().getIndication());
		Assert.assertEquals(14, xcv.getConstraint().size());
	}

	@Test
	public void CertificateValidationWithExpiredCertificate() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithExpiredSigningCertificate();

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(),
				Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xcv.getConclusion().getSubIndication());
		Assert.assertEquals(1, xcv.getConstraint().size());
	}

	@Test
	public void CertificateValidationCurrentTimeNotInValidityRangeOfTheSignerCertificate() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithRevokedSigningCertificate();

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		Calendar cal = Calendar.getInstance();
		cal.setTime(new Date());
		cal.add(Calendar.DATE, 740);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), cal.getTime(),
				Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xcv.getConclusion().getSubIndication());
		Assert.assertEquals(1, xcv.getConstraint().size());
	}

	@Test
	public void CertificateValidationWithSignatureCertificateNotValid() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataCertificateSignatureNonValid();

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(),
				Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, xcv.getConclusion().getSubIndication());
		Assert.assertEquals(4, xcv.getConstraint().size());
	}

	@Test
	public void CertificateValidationWithNoRevocationData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithNoRevocationData();

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(),
				Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.TRY_LATER, xcv.getConclusion().getSubIndication());
		Assert.assertEquals(5, xcv.getConstraint().size());
	}

	@Test
	public void CertificateValidationWithRevocationDataNotTrusted() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithRevocationDataNotTrusted();

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(),
				Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.TRY_LATER, xcv.getConclusion().getSubIndication());
		Assert.assertEquals(6, xcv.getConstraint().size());
	}

	@Test
	public void CertificateValidationWithRevokedCertificate() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithRevokedSigningCertificate();

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(),
				Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.REVOKED_NO_POE, xcv.getConclusion().getSubIndication());
		Assert.assertEquals(7, xcv.getConstraint().size());
		Assert.assertEquals(1, xcv.getConstraint().get(xcv.getConstraint().size() - 1).getInfo().size());
	}

	@Test
	public void PolicyWithSSCDAsFailLevel() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithWrongEncriptionAlgo();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getSigningCertificateSupportedBySSCDConstraint(Context.SIGNATURE).setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(),
				Context.SIGNATURE, policy);
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, xcv.getConclusion().getSubIndication());
		Assert.assertEquals(13, xcv.getConstraint().size());
	}

	@Test
	public void PolicyWithIssuerAsFailLevel() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithWrongEncriptionAlgo();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getSigningCertificateIssuedToLegalPersonConstraint(Context.SIGNATURE).setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(),
				Context.SIGNATURE, policy);
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, xcv.getConclusion().getSubIndication());
		Assert.assertEquals(14, xcv.getConstraint().size());
	}

	@Test
	public void PolicyWithQualifiedSignerCertificateAsFailLevel() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithWrongEncriptionAlgo();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getSigningCertificateQualificationConstraint(Context.SIGNATURE).setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(),
				Context.SIGNATURE, policy);
		XmlXCV xcv = verification.execute();

		for (XmlConstraint constraint : xcv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, xcv.getConclusion().getSubIndication());
		Assert.assertEquals(12, xcv.getConstraint().size());
	}
}
