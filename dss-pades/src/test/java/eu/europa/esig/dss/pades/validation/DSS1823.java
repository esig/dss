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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class DSS1823 extends PKIFactoryAccess {

	private static final String TRUST_ANCHOR = "MIIFwTCCA6mgAwIBAgIQdLjPY4+rcrxGwdK6zQAFDDANBgkqhkiG9w0BAQ0FADBzMRkwFwYDVQQFExBDUEotMi0xMDAtMDk4MzExMQ0wCwYDVQQLEwREQ0ZEMQ8wDQYDVQQKEwZNSUNJVFQxCzAJBgNVBAYTAkNSMSkwJwYDVQQDEyBDQSBSQUlaIE5BQ0lPTkFMIC0gQ09TVEEgUklDQSB2MjAeFw0xNTAyMjQyMjE5NTVaFw0zOTAyMjQyMjI4NDRaMHMxGTAXBgNVBAUTEENQSi0yLTEwMC0wOTgzMTExDTALBgNVBAsTBERDRkQxDzANBgNVBAoTBk1JQ0lUVDELMAkGA1UEBhMCQ1IxKTAnBgNVBAMTIENBIFJBSVogTkFDSU9OQUwgLSBDT1NUQSBSSUNBIHYyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwnQxZdkRRU4vV9xiuV3HStB/7o3GB95pZL/NgdVXrSc+X1hxGtwgwPyrc/SrLodUpXBYWD0zQNSQWkPpXkRoSa7guAjyHDpmfDkbRk2Oj414OpN3Etoehrw9pBWgHrFK1e5+oj2iHj1QRBUPlcyKJTz+DyOgvY2wC5Tgyxj4Fn2Tqy79Ck6UlerJgp8xRbPJwuF/2apBlzXu+/zvV3Pv2MMrPvSMpVK0oAw47TLpSzNRG3Z88V9PhPdkEyvqstdWQHiuFp49ulRvsr1cRdmkNptO0q6udPyej3k50Dl8IzhW1Uv5yPCKpxpDpoyy3X6HnfmZ470lbhzTZ12AQ392ansLLnO/ZOT4E9JB1M2UiZox8TdGe5RKDNQGK2GWJIQKDsIZqcVCmbGrCRPxCOtC/NwILxQCu8k1TkeH8SlrkwiBMsoCu5qeNrkarQxEYcVNXyw0rAaofaNL/42a5x7ulg78bNFBMj3vXM81WyFt+K3Ef+Zzd94ib/iOuzajKCIxiI+lp0PaNiVgj4a3h5BJM74umhCv0U+TAqIljp5QqPJvikcT4PgU4OS9/kCNxpKYqHJzRoijHWeA+EOSlAnuztya9KQLzmzoC/gQ4hqVfk2UNQ57DKdkuPbBTFvCSTjzRV+J7lfpci+WhT1BCRgUKSIwGEHYOm1dvjWOydRQBzcCAwEAAaNRME8wCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFODy/n3ERE5Q5DX9CImPToQZRDNAMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBDQUAA4ICAQBJ5nSJMjsLLttbQWOESI3JjGtP7LIEIQCMAjM7WJTmUDMK1Xd+LKGq/vMzv0OnlCVsM4D7pnpWyEU30n9BvwCk4/bcp/ka/NBbE0fXNVF2px0T369RmfSBR32+y67kwfV9wT2lsm1M6faOCtLXgOe0UaCD5shbegU8RQhk2owSQTj6ZeXKQSnr5dv6z4nE5hFUFCMWYvbO9Lq9EyzzzMOEbV4fOu9PVgPQ5wARzJ0pf0evH9SnId5Y1nvSAYkHPgoiqiaSlcy9nN2C+QHwvt89nIH4krkSp0bLjX7ww8UgSzJnmrwWrjqt0c+OpOEkBlkmz2WeRK6G7fvov8SFSjZkMaiAKRHbxAuDSs+HAG9xzrI7OjvaLuVq5w0r3p77XT70Hiv6M/8ysMP3FpjNcK8xHjtOupjqVhK+KqBAhC8Z7fIyPH8U2vXPexCO449G930dnK4S8S6CpCh4bdRuZg/n+vRa9Cf/GheO56aANt+unoPf1tfYhKcFGx40lSBxoQtx6eR8TMhuQBJBwd4IRG/cy6ysE0vF2WKikc+m7a8vJYk+Did3n3nHKFKABh0Fdf6Id1/KiyXO0ivm1xR7uK0mreiETRcWa7Pw2D1NllnuoIyx1gsc0eYmZnZC5lV7VBt1xfpCyaRtmcqU7Jzvk/rl9U8rMSpaOcySGf15dGPVtQ==";

	private static final String FILE = "/validation/doc-firmado-LT.pdf";

	@Test
	public void testDataNotIntactLTWithDigest() throws Exception {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream(FILE));

		try (PdfDocumentReader pdDocument = loadPDFDocument(dssDocument)) {
			Collection<PdfSignatureDictionary> signatureDictionaries = pdDocument.extractSigDictionaries().keySet();

			for (PdfSignatureDictionary pdSignature : signatureDictionaries) {

				byte[] cmsContent = pdSignature.getContents();
				byte[] revisionContent = PAdESUtils.getRevisionContent(dssDocument, pdSignature.getByteRange());
				byte[] signedContent = PAdESUtils.getSignedContentFromRevision(revisionContent, pdSignature.getByteRange());

				DSSDocument cmsDocument = new InMemoryDocument(cmsContent);

				CMSDocumentValidator validator = new CMSDocumentValidator(cmsDocument);

				List<DSSDocument> detachedContents = new ArrayList<>();
				InMemoryDocument complete = new InMemoryDocument(signedContent);

				DSSDocument digestDoc = new DigestDocument(DigestAlgorithm.SHA256,
						complete.getDigest(DigestAlgorithm.SHA1));
				detachedContents.add(digestDoc);

				validator.setDetachedContents(detachedContents);

				CommonCertificateVerifier certificateVerifier = getCertificateVerifier(pdDocument);

				validator.setCertificateVerifier(certificateVerifier);

				Reports reports = validator.validateDocument();
//				reports.print();
				DiagnosticData diagnosticData = reports.getDiagnosticData();

				SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
				assertNull(signatureById.getClaimedSigningTime());

				List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
				assertEquals(1, digestMatchers.size());

				XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
				assertEquals(DigestMatcherType.MESSAGE_DIGEST, xmlDigestMatcher.getType());
				assertEquals(DigestAlgorithm.SHA256, xmlDigestMatcher.getDigestMethod());
				assertNotNull(xmlDigestMatcher.getDigestValue());
				assertTrue(xmlDigestMatcher.isDataFound());
				assertFalse(xmlDigestMatcher.isDataIntact());

			}
		}
	}
	
	protected abstract PdfDocumentReader loadPDFDocument(DSSDocument dssDocument);

	@Test
	public void testDataIntactLTWithDigest() throws Exception {

		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream(FILE));

		try (PdfDocumentReader pdDocument = loadPDFDocument(dssDocument)) {
			Collection<PdfSignatureDictionary> signatureDictionaries = pdDocument.extractSigDictionaries().keySet();

			for (PdfSignatureDictionary pdSignature : signatureDictionaries) {

				byte[] cmsContent = pdSignature.getContents();
				byte[] revisionContent = PAdESUtils.getRevisionContent(dssDocument, pdSignature.getByteRange());
				byte[] signedContent = PAdESUtils.getSignedContentFromRevision(revisionContent, pdSignature.getByteRange());

				DSSDocument cmsDocument = new InMemoryDocument(cmsContent);

				CMSDocumentValidator validator = new CMSDocumentValidator(cmsDocument);

				List<DSSDocument> detachedContents = new ArrayList<>();
				InMemoryDocument complete = new InMemoryDocument(signedContent);

				DSSDocument digestDoc = new DigestDocument(DigestAlgorithm.SHA256,
						complete.getDigest(DigestAlgorithm.SHA256));
				detachedContents.add(digestDoc);

				validator.setDetachedContents(detachedContents);

				CommonCertificateVerifier certificateVerifier = getCertificateVerifier(pdDocument);

				validator.setCertificateVerifier(certificateVerifier);

				Reports reports = validator.validateDocument();
//				reports.print();
				DiagnosticData diagnosticData = reports.getDiagnosticData();

				SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
				assertNull(signatureById.getClaimedSigningTime());

				List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
				assertEquals(1, digestMatchers.size());

				XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
				assertEquals(DigestMatcherType.MESSAGE_DIGEST, xmlDigestMatcher.getType());
				assertEquals(DigestAlgorithm.SHA256, xmlDigestMatcher.getDigestMethod());
				assertNotNull(xmlDigestMatcher.getDigestValue());
				assertTrue(xmlDigestMatcher.isDataFound());
				assertTrue(xmlDigestMatcher.isDataIntact());

			}
		}
	}
	
	@Test
	public void testDataIntactLTWithCompleteDocument() throws Exception {

		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream(FILE));

		try (PdfDocumentReader pdDocument = loadPDFDocument(dssDocument)) {
			Collection<PdfSignatureDictionary> signatureDictionaries = pdDocument.extractSigDictionaries().keySet();

			for (PdfSignatureDictionary pdSignature : signatureDictionaries) {

				byte[] cmsContent = pdSignature.getContents();
				byte[] revisionContent = PAdESUtils.getRevisionContent(dssDocument, pdSignature.getByteRange());
				byte[] signedContent = PAdESUtils.getSignedContentFromRevision(revisionContent, pdSignature.getByteRange());

				DSSDocument cmsDocument = new InMemoryDocument(cmsContent);

				CMSDocumentValidator validator = new CMSDocumentValidator(cmsDocument);

				List<DSSDocument> detachedContents = new ArrayList<>();
				InMemoryDocument complete = new InMemoryDocument(signedContent);
				detachedContents.add(complete);

				validator.setDetachedContents(detachedContents);

				CommonCertificateVerifier certificateVerifier = getCertificateVerifier(pdDocument);

				validator.setCertificateVerifier(certificateVerifier);

				Reports reports = validator.validateDocument();
//				reports.print();
				DiagnosticData diagnosticData = reports.getDiagnosticData();

				SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
				assertNull(signatureById.getClaimedSigningTime());

				List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
				assertEquals(1, digestMatchers.size());

				XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
				assertEquals(DigestMatcherType.MESSAGE_DIGEST, xmlDigestMatcher.getType());
				assertEquals(DigestAlgorithm.SHA256, xmlDigestMatcher.getDigestMethod());
				assertNotNull(xmlDigestMatcher.getDigestValue());
				assertTrue(xmlDigestMatcher.isDataFound());
				assertTrue(xmlDigestMatcher.isDataIntact());

			}
		}
	}
	
	private CommonCertificateVerifier getCertificateVerifier(PdfDocumentReader documentReader) throws IOException {
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setTrustedCertSources(getTrustedCertSource());
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		certificateVerifier.setOcspSource(new OnlineOCSPSource());
		certificateVerifier.setCrlSource(new OnlineCRLSource());
		return certificateVerifier;
	}

	private CertificateSource getTrustedCertSource() {
		CertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(TRUST_ANCHOR));
		return trustedCertSource;
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
