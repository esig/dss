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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcSSCD;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.enumerations.QCStatement;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
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

public class QualifiedTest {

	private static final String UNKNOWN_OID = "0.0.0";

	public final static Date PRE_EIDAS_DATE = DatatypeConverter.parseDateTime("2015-07-01T00:00:00.000Z").getTime();

	public final static Date POST_EIDAS_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00.000Z").getTime();

	// --------------------- PRE EIDAS

	@Test
	public void testPreNoQcStatementNoCertPolicy() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(), Collections.emptyList());
		notQC(signingCertificate);
	}

	@Test
	public void testPreQcCompliant() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE), Collections.emptyList());
		qc(signingCertificate);
	}

	@Test
	public void testPreUnknownQcCompliant() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatement.QC_LIMIT_VALUE), Collections.emptyList());
		notQC(signingCertificate);
	}

	@Test
	public void testPreQCP() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(), Arrays.asList(CertificatePolicy.QCP_PUBLIC.getOid()));
		qc(signingCertificate);
	}

	@Test
	public void testPreQCPPlus() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		qc(signingCertificate);
	}

	@Test
	public void testPreUnknownCertPolicy() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(), Arrays.asList(UNKNOWN_OID));
		notQC(signingCertificate);
	}

	@Test
	public void testPreQcTypeEsigOnly() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.emptyList(), Collections.emptyList(),
				Arrays.asList(QCTypeEnum.QCT_ESIGN));
		notQC(signingCertificate);
	}

	// --------------------- POST EIDAS

	@Test
	public void testPostNoQcStatementNoCertPolicy() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(), Collections.emptyList());
		notQC(signingCertificate);
	}

	@Test
	public void testPostQcCompliant() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE), Collections.emptyList());
		qc(signingCertificate);
	}

	@Test
	public void testPostUnknownQcCompliant() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_LIMIT_VALUE), Collections.emptyList());
		notQC(signingCertificate);
	}

	@Test
	public void testPostQCP() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(), Arrays.asList(CertificatePolicy.QCP_PUBLIC.getOid()));
		notQC(signingCertificate); // QcCompliant is missing
	}

	@Test
	public void testPostQcCompliantQCP() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC.getOid()));
		qc(signingCertificate);
	}

	@Test
	public void testPostQCPPlus() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		notQC(signingCertificate); // QcCompliant is missing
	}

	@Test
	public void testPostQcCompliantQCPPlus() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		qc(signingCertificate);
	}

	@Test
	public void testPostQcTypeEsigOnly() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.emptyList(), Collections.emptyList(),
				Arrays.asList(QCTypeEnum.QCT_ESIGN));
		notQC(signingCertificate);
	}

	@Test
	public void testPostQcCompliantQcTypeEsig() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE), Collections.emptyList(),
				Arrays.asList(QCTypeEnum.QCT_ESIGN));
		qc(signingCertificate);
	}

	@Test
	public void testPostQcCompliantQcTypeEseals() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE), Collections.emptyList(),
				Arrays.asList(QCTypeEnum.QCT_ESEAL));
		qc(signingCertificate);
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

	private void notQC(CertificateWrapper signingCertificate) {
		QualificationStrategy strategy = QualificationStrategyFactory.createQualificationFromCert(signingCertificate);
		assertFalse(CertificateQualifiedStatus.isQC(strategy.getQualifiedStatus()));
	}

	private void qc(CertificateWrapper signingCertificate) {
		QualificationStrategy strategy = QualificationStrategyFactory.createQualificationFromCert(signingCertificate);
		assertTrue(CertificateQualifiedStatus.isQC(strategy.getQualifiedStatus()));
	}

}
