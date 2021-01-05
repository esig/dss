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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.QCStatement;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;

public class QualifiedTest {

	private static final String UNKNOWN_OID = "0.0.0";

	public final static Date PRE_EIDAS_DATE = DatatypeConverter.parseDateTime("2015-07-01T00:00:00.000Z").getTime();

	public final static Date POST_EIDAS_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00.000Z").getTime();

	// --------------------- PRE EIDAS

	@Test
	public void testPreNoQcStatementNoCertPolicy() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(), Collections.<String> emptyList());
		notQC(signingCertificate);
	}

	@Test
	public void testPreQcCompliant() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE.getOid()), Collections.<String> emptyList());
		qc(signingCertificate);
	}

	@Test
	public void testPreUnknownQcCompliant() {
		CertificateWrapper signingCertificate = createPreEIDAS(Arrays.asList(UNKNOWN_OID), Collections.<String> emptyList());
		notQC(signingCertificate);
	}

	@Test
	public void testPreQCP() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(), Arrays.asList(CertificatePolicy.QCP_PUBLIC.getOid()));
		qc(signingCertificate);
	}

	@Test
	public void testPreQCPPlus() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		qc(signingCertificate);
	}

	@Test
	public void testPreUnknownCertPolicy() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(), Arrays.asList(UNKNOWN_OID));
		notQC(signingCertificate);
	}

	@Test
	public void testPreQcTypeEsigOnly() {
		CertificateWrapper signingCertificate = createPreEIDAS(Collections.<String> emptyList(), Collections.<String> emptyList(),
				Arrays.asList(QCStatement.QCT_ESIGN.getOid()));
		notQC(signingCertificate);
	}

	// --------------------- POST EIDAS

	@Test
	public void testPostNoQcStatementNoCertPolicy() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(), Collections.<String> emptyList());
		notQC(signingCertificate);
	}

	@Test
	public void testPostQcCompliant() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE.getOid()), Collections.<String> emptyList());
		qc(signingCertificate);
	}

	@Test
	public void testPostUnknownQcCompliant() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(UNKNOWN_OID), Collections.<String> emptyList());
		notQC(signingCertificate);
	}

	@Test
	public void testPostQCP() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(), Arrays.asList(CertificatePolicy.QCP_PUBLIC.getOid()));
		notQC(signingCertificate); // QcCompliant is missing
	}

	@Test
	public void testPostQcCompliantQCP() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE.getOid()),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC.getOid()));
		qc(signingCertificate);
	}

	@Test
	public void testPostQCPPlus() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		notQC(signingCertificate); // QcCompliant is missing
	}

	@Test
	public void testPostQcCompliantQCPPlus() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE.getOid()),
				Arrays.asList(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid()));
		qc(signingCertificate);
	}

	@Test
	public void testPostQcTypeEsigOnly() {
		CertificateWrapper signingCertificate = createPostEIDAS(Collections.<String> emptyList(), Collections.<String> emptyList(),
				Arrays.asList(QCStatement.QCT_ESIGN.getOid()));
		notQC(signingCertificate);
	}

	@Test
	public void testPostQcCompliantQcTypeEsig() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE.getOid()), Collections.<String> emptyList(),
				Arrays.asList(QCStatement.QCT_ESIGN.getOid()));
		qc(signingCertificate);
	}

	@Test
	public void testPostQcCompliantQcTypeEseals() {
		CertificateWrapper signingCertificate = createPostEIDAS(Arrays.asList(QCStatement.QC_COMPLIANCE.getOid()), Collections.<String> emptyList(),
				Arrays.asList(QCStatement.QCT_ESEAL.getOid()));
		qc(signingCertificate);
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
		List<XmlCertificatePolicy> cerPolicies = new ArrayList<>();
		for (String oid : certificatePolicyIds) {
			XmlCertificatePolicy cp = new XmlCertificatePolicy();
			cp.setValue(oid);
			cerPolicies.add(cp);
		}
		return cerPolicies;
	}

	private List<XmlOID> toOids(List<String> oids) {
		List<XmlOID> result = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(oids)) {
			for (String oid : oids) {
				XmlOID xmlOid = new XmlOID();
				xmlOid.setValue(oid);
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
