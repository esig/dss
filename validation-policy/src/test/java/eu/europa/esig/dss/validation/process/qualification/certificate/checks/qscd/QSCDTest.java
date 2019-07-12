/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.QCStatement;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificatePolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOID;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.certificate.QSCDStatus;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QSCDTest {

	private static final String UNKNOWN_OID = "0.0.0";

	public final static Date PRE_EIDAS_DATE = DatatypeConverter.parseDateTime("2015-07-01T00:00:00.000Z").getTime();

	public final static Date POST_EIDAS_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00.000Z").getTime();

	private static final QSCDStrategy QSCDTrue = new QSCDStrategy() {

		@Override
		public QSCDStatus getQSCDStatus() {
			return QSCDStatus.QSCD;
		}
	};

	private static final QSCDStrategy QSCDFalse = new QSCDStrategy() {

		@Override
		public QSCDStatus getQSCDStatus() {
			return QSCDStatus.NOT_QSCD;
		}
	};

	// --------------------- PRE EIDAS

	@Test
	public void testPreEmpty() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(), Collections.<String> emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	public void testPreQSCDStatement() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatement.QC_SSCD.getOid()), Collections.<String> emptyList());
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
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
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
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_SSCD.getOid()), Collections.<String> emptyList());
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
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
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
		notQSCD(null, QualifiedStatus.QC, QSCDTrue);
	}

	@Test
	public void trustedServiceButNoQC() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		notQSCD(service, QualifiedStatus.NOT_QC, QSCDTrue);
	}

	@Test
	public void trustedServiceNoOverules() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		qscd(service, QualifiedStatus.QC, QSCDTrue);
	}

	@Test
	public void trustedServiceOverrulesNotQSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_NO_QSCD));
		notQSCD(service, QualifiedStatus.QC, QSCDTrue);
	}

	@Test
	public void trustedServiceOverrulesQSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF));
		qscd(service, QualifiedStatus.QC, QSCDFalse);
	}

	@Test
	public void trustedServiceOverrulesQSCDAsInCert() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_QSCD_STATUS_AS_IN_CERT));
		notQSCD(service, QualifiedStatus.QC, QSCDFalse);
	}

	@Test
	public void trustedServiceUnknownOverrule() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList("Test"));
		notQSCD(service, QualifiedStatus.QC, QSCDFalse);
	}

	private CertificateWrapper createPreEIDAS(List<String> qcStatementIds, List<String> certificatePolicyIds) {
		return createPreEIDAS(qcStatementIds, certificatePolicyIds, Collections.<String> emptyList());
	}

	private CertificateWrapper createPreEIDAS(List<String> qcStatementIds, List<String> certificatePolicyIds, List<String> qcTypeIds) {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setNotBefore(PRE_EIDAS_DATE);
		xmlCert.setQCStatementIds(toOids(qcStatementIds));
		xmlCert.setCertificatePolicies(toCertPolicies(certificatePolicyIds));
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
		xmlCert.setCertificatePolicies(toCertPolicies(certificatePolicyIds));
		xmlCert.setQCTypes(toOids(qcTypeIds));
		return new CertificateWrapper(xmlCert);
	}

	private List<XmlCertificatePolicy> toCertPolicies(List<String> certificatePolicyIds) {
		List<XmlCertificatePolicy> cerPolicies = new ArrayList<XmlCertificatePolicy>();
		for (String oid : certificatePolicyIds) {
			XmlCertificatePolicy cp = new XmlCertificatePolicy();
			cp.setValue(oid);
			cerPolicies.add(cp);
		}
		return cerPolicies;
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
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromCert(signingCertificate);
		assertTrue(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}

	private void qscd(TrustedServiceWrapper trustedService, QualifiedStatus qualified, QSCDStrategy qscdInCert) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromTL(trustedService, qualified, qscdInCert);
		assertTrue(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}

	private void notQSCD(CertificateWrapper signingCertificate) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromCert(signingCertificate);
		assertFalse(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}

	private void notQSCD(TrustedServiceWrapper trustedService, QualifiedStatus qualified, QSCDStrategy qscdInCert) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromTL(trustedService, qualified, qscdInCert);
		assertFalse(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}
}
