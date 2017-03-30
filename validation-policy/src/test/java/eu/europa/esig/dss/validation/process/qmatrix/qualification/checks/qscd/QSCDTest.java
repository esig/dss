package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import eu.europa.esig.dss.CertificatePolicyOids;
import eu.europa.esig.dss.QCStatementOids;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOID;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.ConditionBuilder;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QSCDTest {

	private static final String UNKNOWN_OID = "0.0.0";

	public final static Date PRE_EIDAS_DATE = DatatypeConverter.parseDateTime("2015-07-01T00:00:00.000Z").getTime();

	public final static Date POST_EIDAS_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00.000Z").getTime();

	// --------------------- PRE EIDAS

	@Test
	public void testPreEmpty() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(), Collections.<String> emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	public void testPreQSCDStatement() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatementOids.QC_SSCD.getOid()), Collections.<String> emptyList());
		qscd(signingCertificate);
	}

	@Test
	public void testPreUnknownStatement() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(UNKNOWN_OID), Collections.<String> emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	public void testPreQSCDPolicyId() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(),
				Arrays.asList(CertificatePolicyOids.QCP_PUBLIC_WITH_SSCD.getOid()));
		qscd(signingCertificate);
	}

	@Test
	public void testPreUnknownPolicyId() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(), Arrays.asList(UNKNOWN_OID));
		notQSCD(signingCertificate);
	}

	// --------------------- POST EIDAS

	@Test
	public void testPostEmpty() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(), Collections.<String> emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	public void testPostQSCDStatement() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatementOids.QC_SSCD.getOid()), Collections.<String> emptyList());
		qscd(signingCertificate);
	}

	@Test
	public void testPostUnknownStatement() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(UNKNOWN_OID), Collections.<String> emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	public void testPostQSCDPolicyId() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(),
				Arrays.asList(CertificatePolicyOids.QCP_PUBLIC_WITH_SSCD.getOid()));
		notQSCD(signingCertificate);
	}

	@Test
	public void testPostUnknownPolicyId() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(), Arrays.asList(UNKNOWN_OID));
		notQSCD(signingCertificate);
	}

	// -------------------- Overrules

	@Test
	public void trustedServiceNull() {
		notQSCD(null, ConditionBuilder.condTrue(), ConditionBuilder.condTrue());
	}

	@Test
	public void trustedServiceButNoQC() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		notQSCD(Arrays.asList(service), ConditionBuilder.condFalse(), ConditionBuilder.condTrue());
	}

	@Test
	public void trustedServiceNoOverules() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		qscd(Arrays.asList(service), ConditionBuilder.condTrue(), ConditionBuilder.condTrue());
	}

	@Test
	public void trustedServiceOverrulesNotQSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_NO_QSCD));
		notQSCD(Arrays.asList(service), ConditionBuilder.condTrue(), ConditionBuilder.condTrue());
	}

	@Test
	public void trustedServiceOverrulesQSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF));
		qscd(Arrays.asList(service), ConditionBuilder.condTrue(), ConditionBuilder.condFalse());
	}

	@Test
	public void trustedServiceOverrulesQSCDAsInCert() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_QSCD_STATUS_AS_IN_CERT));
		notQSCD(Arrays.asList(service), ConditionBuilder.condTrue(), ConditionBuilder.condFalse());
	}

	@Test
	public void trustedServiceUnknownOverrule() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList("Test"));
		notQSCD(Arrays.asList(service), ConditionBuilder.condTrue(), ConditionBuilder.condFalse());
	}

	private CertificateWrapper createPreEIDAS(List<String> qcStatementIds, List<String> certificatePolicyIds) {
		return createPreEIDAS(qcStatementIds, certificatePolicyIds, Collections.<String> emptyList());
	}

	private CertificateWrapper createPreEIDAS(List<String> qcStatementIds, List<String> certificatePolicyIds, List<String> qcTypeIds) {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setNotBefore(PRE_EIDAS_DATE);
		xmlCert.setQCStatementIds(toOids(qcStatementIds));
		xmlCert.setCertificatePolicyIds(toOids(certificatePolicyIds));
		xmlCert.setQCTypes(toOids(qcTypeIds));
		return new CertificateWrapper(xmlCert);
	}

	private CertificateWrapper createPostEIDAS(List<String> qcStatementIds, List<String> certificatePolicyIds) {
		return createPostEIDAS(qcStatementIds, certificatePolicyIds, Collections.<String> emptyList());
	}

	private CertificateWrapper createPostEIDAS(List<String> qcStatementIds, List<String> certificatePolicyIds, List<String> qcTypeIds) {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setNotBefore(POST_EIDAS_DATE);
		xmlCert.setQCStatementIds(toOids(qcStatementIds));
		xmlCert.setCertificatePolicyIds(toOids(certificatePolicyIds));
		xmlCert.setQCTypes(toOids(qcTypeIds));
		return new CertificateWrapper(xmlCert);
	}

	private List<XmlOID> toOids(List<String> oids) {
		List<XmlOID> result = new ArrayList<XmlOID>();
		if (Utils.isCollectionNotEmpty(oids)) {
			for (String oid : oids) {
				XmlOID xmlOid = new XmlOID();
				xmlOid.setValue(oid);
				result.add(xmlOid);
			}
		}
		return result;
	}

	private void qscd(CertificateWrapper signingCertificate) {
		Condition condition = QSCDConditionFactory.createQSCDFromCert(signingCertificate);
		assertTrue(condition.check());
	}

	private void qscd(List<TrustedServiceWrapper> trustedServices, Condition qualified, Condition qscdInCert) {
		Condition condition = QSCDConditionFactory.createQSCDFromTL(trustedServices, qualified, qscdInCert);
		assertTrue(condition.check());
	}

	private void notQSCD(CertificateWrapper signingCertificate) {
		Condition condition = QSCDConditionFactory.createQSCDFromCert(signingCertificate);
		assertFalse(condition.check());
	}

	private void notQSCD(List<TrustedServiceWrapper> trustedServices, Condition qualified, Condition qscdInCert) {
		Condition condition = QSCDConditionFactory.createQSCDFromTL(trustedServices, qualified, qscdInCert);
		assertFalse(condition.check());
	}
}
