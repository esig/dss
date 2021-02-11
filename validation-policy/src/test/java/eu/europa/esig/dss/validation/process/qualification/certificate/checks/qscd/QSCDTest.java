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

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcQSCD;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.enumerations.QCStatement;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.QSCDStatus;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(), Collections.emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	public void testPreQSCDStatement() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatement.QC_SSCD), Collections.emptyList());
		qscd(signingCertificate);
	}

	@Test
	public void testPreUnknownStatement() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatement.QC_LIMIT_VALUE), Collections.emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	public void testPreQSCDPolicyId() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		qscd(signingCertificate);
	}

	@Test
	public void testPreUnknownPolicyId() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(), Arrays.asList(UNKNOWN_OID));
		notQSCD(signingCertificate);
	}

	// --------------------- POST EIDAS

	@Test
	public void testPostEmpty() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(), Collections.emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	public void testPostQSCDStatement() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_SSCD), Collections.emptyList());
		qscd(signingCertificate);
	}

	@Test
	public void testPostUnknownStatement() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_LIMIT_VALUE), Collections.emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	public void testPostQSCDPolicyId() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		notQSCD(signingCertificate);
	}

	@Test
	public void testPostUnknownPolicyId() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(), Arrays.asList(UNKNOWN_OID));
		notQSCD(signingCertificate);
	}

	// -------------------- Overrules

	@Test
	public void trustedServiceNull() {
		notQSCD(null, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	public void trustedServiceButNoQC() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		notQSCD(service, CertificateQualifiedStatus.NOT_QC, QSCDTrue);
	}

	@Test
	public void trustedServiceNoOverules() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		qscd(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	public void trustedServiceOverrulesNotQSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_NO_QSCD));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	public void trustedServiceOverrulesQSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF));
		qscd(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	public void trustedServiceOverrulesQSCDAsInCert() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_QSCD_STATUS_AS_IN_CERT));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	public void trustedServiceUnknownOverrule() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList("Test"));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	private CertificateWrapper createPreEIDAS(List<OidDescription> qcStatementIds, List<String> certificatePolicyIds) {
		return createPreEIDAS(qcStatementIds, certificatePolicyIds, Collections.emptyList());
	}

	private CertificateWrapper createPreEIDAS(List<OidDescription> qcStatementIds, List<String> certificatePolicyIds, List<QCType> qcTypes) {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setNotBefore(PRE_EIDAS_DATE);
		xmlCert.setCertificatePolicies(toCertPolicies(certificatePolicyIds));

		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setQcTypes(toOids(qcTypes));
		if (qcStatementIds.contains(QCStatement.QC_SSCD)) {
			XmlQcQSCD xmlQscd = new XmlQcQSCD();
			xmlQscd.setPresent(true);
			xmlQcStatements.setQcQSCD(xmlQscd);
		}
		if (qcStatementIds.contains(QCStatement.QC_COMPLIANCE)) {
			XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
			xmlQcCompliance.setPresent(true);
			xmlQcStatements.setQcCompliance(xmlQcCompliance);
		}
		xmlCert.setQcStatements(xmlQcStatements);
		return new CertificateWrapper(xmlCert);
	}

	private CertificateWrapper createPostEIDAS(List<OidDescription> qcStatementIds, List<String> certificatePolicyIds) {
		return createPostEIDAS(qcStatementIds, certificatePolicyIds, Collections.emptyList());
	}

	private CertificateWrapper createPostEIDAS(List<OidDescription> qcStatementIds, List<String> certificatePolicyIds, List<QCType> qcTypes) {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setNotBefore(POST_EIDAS_DATE);
		xmlCert.setCertificatePolicies(toCertPolicies(certificatePolicyIds));

		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setQcTypes(toOids(qcTypes));
		if (qcStatementIds.contains(QCStatement.QC_SSCD)) {
			XmlQcQSCD xmlQscd = new XmlQcQSCD();
			xmlQscd.setPresent(true);
			xmlQcStatements.setQcQSCD(xmlQscd);
		}
		if (qcStatementIds.contains(QCStatement.QC_COMPLIANCE)) {
			XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
			xmlQcCompliance.setPresent(true);
			xmlQcStatements.setQcCompliance(xmlQcCompliance);
		}
		xmlCert.setQcStatements(xmlQcStatements);
		return new CertificateWrapper(xmlCert);
	}

	private List<XmlCertificatePolicy> toCertPolicies(List<String> certificatePolicyIds) {
		List<XmlCertificatePolicy> cerPolicies = new ArrayList<>();
		for (String oid : certificatePolicyIds) {
			XmlCertificatePolicy cp = new XmlCertificatePolicy();
			cp.setValue(oid);
			cerPolicies.add(cp);
		}
		return cerPolicies;
	}

	private List<XmlOID> toOids(List<QCType> qcTypes) {
		List<XmlOID> result = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(qcTypes)) {
			for (QCType qcType : qcTypes) {
				XmlOID xmlOid = new XmlOID();
				xmlOid.setValue(qcType.getOid());
				result.add(xmlOid);
			}
		}
		return result;
	}

	private void qscd(CertificateWrapper signingCertificate) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromCert(signingCertificate);
		assertTrue(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}

	private void qscd(TrustedServiceWrapper trustedService, CertificateQualifiedStatus qualified, QSCDStrategy qscdInCert) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromTL(trustedService, qualified, qscdInCert);
		assertTrue(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}

	private void notQSCD(CertificateWrapper signingCertificate) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromCert(signingCertificate);
		assertFalse(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}

	private void notQSCD(TrustedServiceWrapper trustedService, CertificateQualifiedStatus qualified, QSCDStrategy qscdInCert) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromTL(trustedService, qualified, qscdInCert);
		assertFalse(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}
}
