package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd;

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
import eu.europa.esig.dss.validation.process.art32.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class SSCDTest {

	private static final String UNKNOWN_OID = "0.0.0";

	public final static Date PRE_EIDAS_DATE = DatatypeConverter.parseDateTime("2015-07-01T00:00:00.000Z").getTime();

	public final static Date POST_EIDAS_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00.000Z").getTime();

	// --------------------- PRE EIDAS

	@Test
	public void testPreEmpty() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(), Collections.<String> emptyList());
		notSSCD(signingCertificate);
	}

	@Test
	public void testPreSSCDStatement() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatementOids.QC_SSCD.getOid()), Collections.<String> emptyList());
		sscd(signingCertificate);
	}

	@Test
	public void testPreUnknownStatement() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(UNKNOWN_OID), Collections.<String> emptyList());
		notSSCD(signingCertificate);
	}

	@Test
	public void testPreSSCDPolicyId() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(),
				Arrays.asList(CertificatePolicyOids.QCP_PUBLIC_WITH_SSCD.getOid()));
		sscd(signingCertificate);
	}

	@Test
	public void testPreUnknownPolicyId() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(), Arrays.asList(UNKNOWN_OID));
		notSSCD(signingCertificate);
	}

	// --------------------- POST EIDAS

	@Test
	public void testPostEmpty() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(), Collections.<String> emptyList());
		notSSCD(signingCertificate);
	}

	@Test
	public void testPostSSCDStatement() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatementOids.QC_SSCD.getOid()), Collections.<String> emptyList());
		sscd(signingCertificate);
	}

	@Test
	public void testPostUnknownStatement() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(UNKNOWN_OID), Collections.<String> emptyList());
		notSSCD(signingCertificate);
	}

	@Test
	public void testPostSSCDPolicyId() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(),
				Arrays.asList(CertificatePolicyOids.QCP_PUBLIC_WITH_SSCD.getOid()));
		notSSCD(signingCertificate);
	}

	@Test
	public void testPostUnknownPolicyId() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(), Arrays.asList(UNKNOWN_OID));
		notSSCD(signingCertificate);
	}

	// -------------------- Overrules

	@Test
	public void trustedServiceNull() {
		notSSCD(null, ConditionBuilder.condTrue(), ConditionBuilder.condTrue());
	}

	@Test
	public void trustedServiceButNoQC() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		notSSCD(service, ConditionBuilder.condFalse(), ConditionBuilder.condTrue());
	}

	@Test
	public void trustedServiceNoOverules() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		sscd(service, ConditionBuilder.condTrue(), ConditionBuilder.condTrue());
	}

	@Test
	public void trustedServiceOverrulesNotSSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_NO_QSCD));
		notSSCD(service, ConditionBuilder.condTrue(), ConditionBuilder.condTrue());
	}

	@Test
	public void trustedServiceOverrulesSSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QCQSCD_STATUS_AS_IN_CERT));
		sscd(service, ConditionBuilder.condTrue(), ConditionBuilder.condFalse());
	}

	@Test
	public void trustedServiceUnknownOverrule() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList("Test"));
		notSSCD(service, ConditionBuilder.condTrue(), ConditionBuilder.condFalse());
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

	private void sscd(CertificateWrapper signingCertificate) {
		Condition condition = SSCDConditionFactory.createSSCDFromCert(signingCertificate);
		assertTrue(condition.check());
	}

	private void sscd(TrustedServiceWrapper trustedService, Condition qualified, Condition sscdInCert) {
		Condition condition = SSCDConditionFactory.createSSCDFromTL(trustedService, qualified, sscdInCert);
		assertTrue(condition.check());
	}

	private void notSSCD(CertificateWrapper signingCertificate) {
		Condition condition = SSCDConditionFactory.createSSCDFromCert(signingCertificate);
		assertFalse(condition.check());
	}

	private void notSSCD(TrustedServiceWrapper trustedService, Condition qualified, Condition sscdInCert) {
		Condition condition = SSCDConditionFactory.createSSCDFromTL(trustedService, qualified, sscdInCert);
		assertFalse(condition.check());
	}
}
