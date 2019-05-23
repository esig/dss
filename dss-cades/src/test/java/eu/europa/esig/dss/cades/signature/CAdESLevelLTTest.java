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
package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

public class CAdESLevelLTTest extends AbstractCAdESTestSignature {

	private DocumentSignatureService<CAdESSignatureParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World".getBytes());

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected CertificateVerifier getOfflineCertificateVerifier() {
		CertificateVerifier certificateVerifier = super.getOfflineCertificateVerifier();
		certificateVerifier.setIncludeCertificateTokenValues(true);
		certificateVerifier.setIncludeCertificateRevocationValues(true);
		certificateVerifier.setIncludeTimestampTokenValues(true);
		return certificateVerifier;
	}

	@Override
	protected void verifyDiagnosticDataJaxb(eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData diagnosticDataJaxb) {
		super.verifyDiagnosticDataJaxb(diagnosticDataJaxb);

		List<XmlCertificate> usedCertificates = diagnosticDataJaxb.getUsedCertificates();
		for (XmlCertificate xmlCertificate : usedCertificates) {
			if (!xmlCertificate.isTrusted() && !xmlCertificate.isIdPkixOcspNoCheck() && !xmlCertificate.isSelfSigned()) {
				List<XmlRevocation> revocations = xmlCertificate.getRevocations();
				assertTrue(Utils.isCollectionNotEmpty(revocations));
				for (XmlRevocation xmlRevocation : revocations) {
					assertNotNull(xmlRevocation.getBase64Encoded());
				}
			}

			if (xmlCertificate.isSelfSigned()) {
				assertNull(xmlCertificate.getSigningCertificate());
				assertTrue(xmlCertificate.getCertificateChain().isEmpty());
			}
		}

		List<XmlSignature> signatures = diagnosticDataJaxb.getSignatures();
		for (XmlSignature xmlSignature : signatures) {
			List<XmlTimestamp> timestamps = xmlSignature.getTimestamps();
			for (XmlTimestamp xmlTimestamp : timestamps) {
				assertNotNull(xmlTimestamp.getBase64Encoded());
			}
		}

		DiagnosticData dd = new DiagnosticData(diagnosticDataJaxb);
		for (CertificateWrapper cert : dd.getUsedCertificates()) {
			CertificateWrapper certificateWrapper = dd.getUsedCertificateById(cert.getId());
			assertNotNull(certificateWrapper);
			assertNotNull(certificateWrapper.getBinaries());
		}
		for (TimestampWrapper tst : dd.getAllTimestamps()) {
			TimestampWrapper timestampWrapper = dd.getTimestampById(tst.getId());
			assertNotNull(timestampWrapper);
			assertNotNull(timestampWrapper.getBinaries());
		}
		for (RevocationWrapper revocation : dd.getAllRevocationData()) {
			RevocationWrapper revocationWrapper = dd.getRevocationDataById(revocation.getId());
			assertNotNull(revocationWrapper);
			assertNotNull(revocationWrapper.getBinaries());
		}
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
