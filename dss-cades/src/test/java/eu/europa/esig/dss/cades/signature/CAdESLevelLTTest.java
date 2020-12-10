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

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESLevelLTTest extends AbstractCAdESTestSignature {

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
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
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		assertEquals(1, diagnosticData.getTimestampList().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, diagnosticData.getTimestampList().iterator().next().getType());
	}

	@Override
	protected TokenExtractionStrategy getTokenExtractionStrategy() {
		return TokenExtractionStrategy.EXTRACT_ALL;
	}

	@Override
	protected void verifyDiagnosticDataJaxb(XmlDiagnosticData diagnosticDataJaxb) {
		super.verifyDiagnosticDataJaxb(diagnosticDataJaxb);

		List<XmlCertificate> usedCertificates = diagnosticDataJaxb.getUsedCertificates();
		for (XmlCertificate xmlCertificate : usedCertificates) {
			if (!xmlCertificate.isTrusted() && !xmlCertificate.isIdPkixOcspNoCheck() && !xmlCertificate.isSelfSigned()) {
				List<XmlCertificateRevocation> revocations = xmlCertificate.getRevocations();
				assertTrue(Utils.isCollectionNotEmpty(revocations));
				for (XmlCertificateRevocation xmlCertificateRevocation : revocations) {
					List<XmlRevocation> xmlRevocations = diagnosticDataJaxb.getUsedRevocations();
					for (XmlRevocation revocation : xmlRevocations) {
						if (xmlCertificateRevocation.getRevocation().getId().equals(revocation.getId())) {
							assertNotNull(revocation.getBase64Encoded());
						}
					}
				}
			}

			if (xmlCertificate.isSelfSigned()) {
				assertNull(xmlCertificate.getSigningCertificate());
				assertTrue(xmlCertificate.getCertificateChain().isEmpty());
			}
		}

		List<XmlTimestamp> timestamps = diagnosticDataJaxb.getUsedTimestamps();
		for (XmlTimestamp xmlTimestamp : timestamps) {
			assertNotNull(xmlTimestamp.getBase64Encoded());
		}

		DiagnosticData dd = new DiagnosticData(diagnosticDataJaxb);
		for (CertificateWrapper cert : dd.getUsedCertificates()) {
			CertificateWrapper certificateWrapper = dd.getUsedCertificateById(cert.getId());
			assertNotNull(certificateWrapper);
			assertNotNull(certificateWrapper.getBinaries());
		}
		for (TimestampWrapper tst : dd.getTimestampSet()) {
			TimestampWrapper timestampWrapper = dd.getTimestampById(tst.getId());
			assertNotNull(timestampWrapper);
			assertNotNull(timestampWrapper.getBinaries());
		}
		for (RevocationWrapper revocation : dd.getAllRevocationData()) {
			assertNotNull(revocation);
			assertNotNull(revocation.getBinaries());
		}
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
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
