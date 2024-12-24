/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcSSCD;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQualifier;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.enumerations.QCStatement;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.QSCDStatus;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import jakarta.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QSCDTest {

	private static final String UNKNOWN_OID = "0.0.0";

	public static final Date PRE_EIDAS_DATE = DatatypeConverter.parseDateTime("2015-07-01T00:00:00.000Z").getTime();

	public static final Date POST_EIDAS_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00.000Z").getTime();

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
	void testPreEmpty() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(), Collections.emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	void testPreQSCDStatement() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatement.QC_SSCD), Collections.emptyList());
		qscd(signingCertificate);
	}

	@Test
	void testPreUnknownStatement() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatement.QC_LIMIT_VALUE), Collections.emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	void testPreQSCDPolicyId() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		qscd(signingCertificate);
	}

	@Test
	void testPreUnknownPolicyId() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(), Arrays.asList(UNKNOWN_OID));
		notQSCD(signingCertificate);
	}

	// --------------------- POST EIDAS

	@Test
	void testPostEmpty() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(), Collections.emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	void testPostQSCDStatement() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_SSCD), Collections.emptyList());
		qscd(signingCertificate);
	}

	@Test
	void testPostUnknownStatement() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_LIMIT_VALUE), Collections.emptyList());
		notQSCD(signingCertificate);
	}

	@Test
	void testPostQSCDPolicyId() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		notQSCD(signingCertificate);
	}

	@Test
	void testPostUnknownPolicyId() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(), Arrays.asList(UNKNOWN_OID));
		notQSCD(signingCertificate);
	}

	// -------------------- Overrules

	@Test
	void trustServiceNull() {
		notQSCD(null, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServicePreEIDASButNoQC() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		notQSCD(service, CertificateQualifiedStatus.NOT_QC, QSCDTrue);
	}

	@Test
	void trustServicePostEIDASButNoQC() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		notQSCD(service, CertificateQualifiedStatus.NOT_QC, QSCDTrue);
	}

	@Test
	void trustServicePreEIDASNoOverrules() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		qscd(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServicePostEIDASNoOverrules() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		qscd(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServiceOverrulesQSCDPreEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri()));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesQSCDPostEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri()));
		qscd(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesNotQSCDPreEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri()));
		qscd(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServiceOverrulesNotQSCDPostEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri()));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServiceOverrulesSSCDPreEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri()));
		qscd(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesSSCDPostEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri()));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesNotSSCDPreEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri()));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServiceOverrulesNotSSCDPostEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri()));
		qscd(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServiceOverrulesQSCDPreEIADS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF.getUri()));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesQSCDPostEIADS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF.getUri()));
		qscd(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesQSCDAsInCertPreEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_STATUS_AS_IN_CERT.getUri()));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesQSCDAsInCertPostEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_STATUS_AS_IN_CERT.getUri()));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesQSCDAsInCertTruePreEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_STATUS_AS_IN_CERT.getUri()));
		qscd(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServiceOverrulesQSCDAsInCertTruePostEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_STATUS_AS_IN_CERT.getUri()));
		qscd(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServiceOverrulesSSCDAsInCertPreEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_SSCD_STATUS_AS_IN_CERT.getUri()));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesSSCDAsInCertPostEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_SSCD_STATUS_AS_IN_CERT.getUri()));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceOverrulesSSCDAsInCertTruePreEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_SSCD_STATUS_AS_IN_CERT.getUri()));
		qscd(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServiceOverrulesSSCDAsInCertTruePostEIDAS() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_SSCD_STATUS_AS_IN_CERT.getUri()));
		qscd(service, CertificateQualifiedStatus.QC, QSCDTrue);
	}

	@Test
	void trustServiceUnknownPreEIDASOverrule() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(PRE_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList("Test"));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	@Test
	void trustServiceUnknownPostEIDASOverrule() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setStartDate(POST_EIDAS_DATE);
		service.setCapturedQualifiers(getXmlQualifierList("Test"));
		notQSCD(service, CertificateQualifiedStatus.QC, QSCDFalse);
	}

	private List<XmlQualifier> getXmlQualifierList(String... uris) {
		List<XmlQualifier> qualifierList = new ArrayList<>();
		for (String uri : uris) {
			XmlQualifier xmlQualifier = new XmlQualifier();
			xmlQualifier.setValue(uri);
			qualifierList.add(xmlQualifier);
		}
		return qualifierList;
	}

	private CertificateWrapper createPreEIDAS(List<OidDescription> qcStatementIds, List<String> certificatePolicyIds) {
		return createPreEIDAS(qcStatementIds, certificatePolicyIds, Collections.emptyList());
	}

	private CertificateWrapper createPreEIDAS(List<OidDescription> qcStatementIds, List<String> certificatePolicyIds, List<QCType> qcTypes) {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setNotBefore(PRE_EIDAS_DATE);
		xmlCert.getCertificateExtensions().add(toCertPolicies(certificatePolicyIds));

		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		xmlQcStatements.setQcTypes(toOids(qcTypes));
		if (qcStatementIds.contains(QCStatement.QC_SSCD)) {
			XmlQcSSCD xmlQcSSCD = new XmlQcSSCD();
			xmlQcSSCD.setPresent(true);
			xmlQcStatements.setQcSSCD(xmlQcSSCD);
		}
		if (qcStatementIds.contains(QCStatement.QC_COMPLIANCE)) {
			XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
			xmlQcCompliance.setPresent(true);
			xmlQcStatements.setQcCompliance(xmlQcCompliance);
		}
		xmlCert.getCertificateExtensions().add(xmlQcStatements);
		return new CertificateWrapper(xmlCert);
	}

	private CertificateWrapper createPostEIDAS(List<OidDescription> qcStatementIds, List<String> certificatePolicyIds) {
		return createPostEIDAS(qcStatementIds, certificatePolicyIds, Collections.emptyList());
	}

	private CertificateWrapper createPostEIDAS(List<OidDescription> qcStatementIds, List<String> certificatePolicyIds, List<QCType> qcTypes) {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setNotBefore(POST_EIDAS_DATE);
		xmlCert.getCertificateExtensions().add(toCertPolicies(certificatePolicyIds));

		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		xmlQcStatements.setQcTypes(toOids(qcTypes));
		if (qcStatementIds.contains(QCStatement.QC_SSCD)) {
			XmlQcSSCD xmlQcSSCD = new XmlQcSSCD();
			xmlQcSSCD.setPresent(true);
			xmlQcStatements.setQcSSCD(xmlQcSSCD);
		}
		if (qcStatementIds.contains(QCStatement.QC_COMPLIANCE)) {
			XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
			xmlQcCompliance.setPresent(true);
			xmlQcStatements.setQcCompliance(xmlQcCompliance);
		}
		xmlCert.getCertificateExtensions().add(xmlQcStatements);
		return new CertificateWrapper(xmlCert);
	}

	private XmlCertificatePolicies toCertPolicies(List<String> certificatePolicyIds) {
		XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
		xmlCertificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
		for (String oid : certificatePolicyIds) {
			XmlCertificatePolicy cp = new XmlCertificatePolicy();
			cp.setValue(oid);
			xmlCertificatePolicies.getCertificatePolicy().add(cp);
		}
		return xmlCertificatePolicies;
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

	private void qscd(TrustServiceWrapper trustService, CertificateQualifiedStatus qualified, QSCDStrategy qscdInCert) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromTL(trustService, qualified, qscdInCert);
		assertTrue(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}

	private void notQSCD(CertificateWrapper signingCertificate) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromCert(signingCertificate);
		assertFalse(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}

	private void notQSCD(TrustServiceWrapper trustService, CertificateQualifiedStatus qualified, QSCDStrategy qscdInCert) {
		QSCDStrategy strategy = QSCDStrategyFactory.createQSCDFromTL(trustService, qualified, qscdInCert);
		assertFalse(QSCDStatus.isQSCD(strategy.getQSCDStatus()));
	}
}
