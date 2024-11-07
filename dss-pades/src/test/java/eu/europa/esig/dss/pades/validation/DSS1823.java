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
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.CompositeRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
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

				DSSDocument cmsDocument = new InMemoryDocument(cmsContent);

				CMSDocumentValidator validator = new CMSDocumentValidator(cmsDocument);

				List<DSSDocument> detachedContents = new ArrayList<>();
				DSSDocument signedContent = new PdfByteRangeDocument(dssDocument, pdSignature.getByteRange());

				DSSDocument digestDoc = new DigestDocument(DigestAlgorithm.SHA256, signedContent.getDigestValue(DigestAlgorithm.SHA1));
				detachedContents.add(digestDoc);

				validator.setDetachedContents(detachedContents);

				CommonCertificateVerifier certificateVerifier = getCertificateVerifier();

				validator.setCertificateVerifier(certificateVerifier);

				Reports reports = validator.validateDocument();
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

				DSSDocument cmsDocument = new InMemoryDocument(cmsContent);

				CMSDocumentValidator validator = new CMSDocumentValidator(cmsDocument);

				List<DSSDocument> detachedContents = new ArrayList<>();
				DSSDocument signedContent = new PdfByteRangeDocument(dssDocument, pdSignature.getByteRange());

				DSSDocument digestDoc = new DigestDocument(DigestAlgorithm.SHA256, signedContent.getDigestValue(DigestAlgorithm.SHA256));
				detachedContents.add(digestDoc);

				validator.setDetachedContents(detachedContents);

				CommonCertificateVerifier certificateVerifier = getCertificateVerifier();

				validator.setCertificateVerifier(certificateVerifier);

				Reports reports = validator.validateDocument();
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

				DSSDocument cmsDocument = new InMemoryDocument(cmsContent);

				CMSDocumentValidator validator = new CMSDocumentValidator(cmsDocument);

				List<DSSDocument> detachedContents = new ArrayList<>();
				DSSDocument signedContent = new PdfByteRangeDocument(dssDocument, pdSignature.getByteRange());
				detachedContents.add(signedContent);

				validator.setDetachedContents(detachedContents);

				CommonCertificateVerifier certificateVerifier = getCertificateVerifier();

				validator.setCertificateVerifier(certificateVerifier);

				Reports reports = validator.validateDocument();
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
	
	private CommonCertificateVerifier getCertificateVerifier() {
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setTrustedCertSources(getTrustedCertSource());
		certificateVerifier.setAIASource(null);
		certificateVerifier.setOcspSource(getCompositeOCSPSource());
		certificateVerifier.setCrlSource(getCompositeCRLSource());
		return certificateVerifier;
	}

	private CertificateSource getTrustedCertSource() {
		CertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(TRUST_ANCHOR));
		return trustedCertSource;
	}

	@Override
	protected CompositeRevocationSource<CRL> getCompositeCRLSource() {
		CompositeRevocationSource<CRL> composite = new CompositeRevocationSource<>();
		LinkedHashMap<String, RevocationSource<CRL>> crlSources = new LinkedHashMap<>();
		crlSources.put("PKICRLSource", pkiCRLSource());
		ExternalResourcesCRLSource externalResourcesCRLSource = new ExternalResourcesCRLSource(
				new InMemoryDocument(Utils.fromBase64("MIIDLDCCARQCAQEwDQYJKoZIhvcNAQENBQAwgYAxGTAXBgNVBAUTEENQSi0yLTEwMC0wOTgzMTExCzAJBgNVBAYTAkNSMQ8wDQYDVQQKEwZNSUNJVFQxDTALBgNVBAsTBERDRkQxNjA0BgNVBAMTLUNBIFBPTElUSUNBIFNFTExBRE8gREUgVElFTVBPIC0gQ09TVEEgUklDQSB2MhcNMTgwNzIzMTY0NzIxWhcNMTgwOTI0MDUwNzIxWqBfMF0wHwYDVR0jBBgwFoAUsLvgCC5LE2jw0IBEA2ekP/8lY/YwEAYJKwYBBAGCNxUBBAMCAQAwCgYDVR0UBAMCARgwHAYJKwYBBAGCNxUEBA8XDTE4MDkyMzE2NTcyMVowDQYJKoZIhvcNAQENBQADggIBALO/iMQkQsbfa0dLV5lMElgi85UXz3nH2ES8wZi+kpmTS6F4cYJ91IchDW2BpqJXxRaKqaNR0qXWgmK2RpDn0wYt+YVaNyzoyN0sHUxDwBXfjuUIJrgKLeqheD/HiC0ZfLkgiRNS1sgVE2n/TY6Kz5emMyTEGpL1BQ1eOcb7rhh2Q1u/smbpoIEamn3UZOIXNSfPxL/2l5HRSPa5xcIYPBJz5OZDd2FmEvw9A15EtTAuV1WNuiKq+P9Ka8UtowXfYYc9+N7qTjFzBPJ8e6N+XaarzKhxcppYt4EUKKWijwt9Y2aZtoOTEjBKfGH7CExu40UBtdXMd5/9ckhMN/Z7svDuXGOWJenStJ/IIww/ncuqaPnqROt+rZ1EwuvaxSXnHQftt0I8JUu/I2NijeKb2GcFXNk0rHTx5/+opk515pWmb+0NBdToIcN1BJxQnhfmtgfN/cAgISZF7szkI2suzmmSAlUvk7hkvV56L4DYIYIriC7TwlQOoJW3zqRwjGG530TRJxzStgX36XiOMy53goHqW/j+3lmk7LkGb/El3sIHLAcgq7n0wTl5DYg5Zy/+UV2lF5I7T1yE49KMWL3kEtVUnU8NBbfA5SCVJvFBb5cGcPAPzss0B+/+Z/KGRjP5XfIac+AOHiSIBJaaOUkucW78AXMPLJLbja55bG2EUczs")),
				new InMemoryDocument(Utils.fromBase64("MIIDKDCCARACAQEwDQYJKoZIhvcNAQENBQAwfTEZMBcGA1UEBRMQQ1BKLTItMTAwLTA5ODMxMTELMAkGA1UEBhMCQ1IxDzANBgNVBAoTBk1JQ0lUVDENMAsGA1UECxMERENGRDEzMDEGA1UEAxMqQ0EgUE9MSVRJQ0EgUEVSU09OQSBGSVNJQ0EgLSBDT1NUQSBSSUNBIHYyFw0xODA3MjMxNjI3NDJaFw0xODA5MjQwNDQ3NDJaoF8wXTAfBgNVHSMEGDAWgBRonWk2y4Rue+qTYRn/WDAd1f9cyzAQBgkrBgEEAYI3FQEEAwIBADAKBgNVHRQEAwIBGDAcBgkrBgEEAYI3FQQEDxcNMTgwOTIzMTYzNzQyWjANBgkqhkiG9w0BAQ0FAAOCAgEAKh+lQVnCQf8r4IvrEIqivbCaJSHsth2zUxclOt/OHWw9AwORJKMPQ+TBjH5KSelWoShGS0xaC47amV6qdXT4h3YgvLq2+MY05/4h1ElDugHbsY6nMPZX1u5e0Y5sVTCXPhg574l9iBB7d4ztMqqea3bDTCVH08h2Q4Q+cn7lBQnmFae8RRtQ2Yhevl9P5i/Mr6J71qnv+QHzNrpSAeZutYFWiKGIqmVj5lXRhRL3lJakP5rhyxJrQpuTmZrVMtFFjAgutGPH8IPrxMOQPpB4HFmn2UGAxBen6Rc1jjvLcyi9km3ptZpgw6D/YYWRpneIdOXrURXtz+N5/nGIk3RXWIXUwucUSX3ytphlWFlAuLHGiDvTuo+dEPYa6svb8S1QDxc1uDudesRTfyYrmh6SEd7eP2oGGoTJeFjZYVbqtU3lgC4yrE8+lmoqeiTsc/OetVyMbq6Rw6yw4E13LrLQyXrXq87ks/aFeXmRucy5/OOGDAbe01rrmwZDXP3tYGVywnbsTeCSch1bfKIM5OJnPbRkz3conSn0EbBhuBffSmmxyQXD7LWXPdnfHNofJqiePP3/pZzYgk91YEwJkZln+pFCrXmWIfR0QG+SmMipwvpl5UywajJNdlp7UiWMfywaTPvXgOq6s4tUAjqs445jH4uUQQKL+QL8Z6o6umq6xwM=")),
				new InMemoryDocument(Utils.fromBase64("MIIDHjCCAQYCAQEwDQYJKoZIhvcNAQENBQAwczEZMBcGA1UEBRMQQ1BKLTItMTAwLTA5ODMxMTENMAsGA1UECxMERENGRDEPMA0GA1UEChMGTUlDSVRUMQswCQYDVQQGEwJDUjEpMCcGA1UEAxMgQ0EgUkFJWiBOQUNJT05BTCAtIENPU1RBIFJJQ0EgdjIXDTE4MDcyMzE2MTQwMloXDTE4MTEyNDA0MzQwMlqgXzBdMB8GA1UdIwQYMBaAFODy/n3ERE5Q5DX9CImPToQZRDNAMBAGCSsGAQQBgjcVAQQDAgEAMAoGA1UdFAQDAgENMBwGCSsGAQQBgjcVBAQPFw0xODExMjMxNjI0MDJaMA0GCSqGSIb3DQEBDQUAA4ICAQCgAO9lWJCNgvmCv7xqryaDBvUJZIj0B51mivYVVRRVDaHrkqpk7zkR/y5wbBY2onvF8fxubY8N1G/JzH2ND7pldW6np4Kh89+szhd+TtCpD/P1rTYWB7TMwe1CD3X68eCSW/AOXhZn5EpFcZbA70/czOll6GfIN+cdinRWHmrG1dJGOB2n0ZpU/Oyqa/kG8bbeat/CkGj7TRiCH9LZyHVsIWlMDwTSOm2uD+G9o+LnY5YTuHJBJ3qk8qsdo0DNxCqgIWAKOWamDN182iwvZXyOqX0gYGFcWONnuzWsRjkE77RRie493lQFEUp1jJsju9gPRFqN7Lrj4+GzJcDZClxA0AXqL2hfH2obhxFPDgmVlXxAmm3c0cs2XaQq89pIt6DC2hC+aldZFPz9cSN/7qGONuKKLf671ZLWeW7izP8VkPNikBUjZBlYOM8ND856CoaYMmb+dYLlkUv4y53d40tI6U+UcaJlTcnn/c+los3PLC5MjZ+D4WCoC9FMkPUT23vBWmaCUPNGqwAnrgw4T7B1dnviXf9TBdlzazdjxP+21ku4pTNE1FeRX9uDP2M/QrV6UeuMXiaWvyLGQtAAlorShjj8NIvGAFqKi74GNv1LMWw8qtoRQNvx4Pub523ebH020Nn/SieKu1LOqIvy4sTn75whmxyjbBSnwLKtV+2YtA=="))
		);
		crlSources.put("ExternalResourcesCRLSource", externalResourcesCRLSource);
		composite.setSources(crlSources);
		return composite;
	}

	@Override
	protected CompositeRevocationSource<OCSP> getCompositeOCSPSource() {
		CompositeRevocationSource<OCSP> composite = new CompositeRevocationSource<>();
		LinkedHashMap<String, RevocationSource<OCSP>> ocspSources = new LinkedHashMap<>();
		ocspSources.put("PKIOCSPSource", pkiOCSPSource());
		ExternalResourcesOCSPSource externalResourcesOCSPSource = new ExternalResourcesOCSPSource(
				new InMemoryDocument(Utils.fromBase64("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"))
		);
		ocspSources.put("OnlineOCSPSource", externalResourcesOCSPSource);
		composite.setSources(ocspSources);
		return composite;
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
