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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Unit test to fix issue https://esig-dss.atlassian.net/browse/DSS-646
 */
public class ExtendToCAdESLtaTest extends AbstractCAdESTestValidation {

	private static final String SIGNED_DOC_PATH = "src/test/resources/validation/dss-646/CAdES_A_DETACHED.csig";
	private static final String DETACHED_DOC_PATH = "src/test/resources/validation/dss-646/document.pdf";

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(SIGNED_DOC_PATH);
	}

	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(new FileDocument(DETACHED_DOC_PATH));
	}

	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		List<RelatedRevocationWrapper> relatedRevocations = signature.foundRevocations().getRelatedRevocationData();
		assertTrue(Utils.isCollectionNotEmpty(relatedRevocations));
		for (RevocationWrapper revocation : relatedRevocations) {
			assertNotNull(revocation);
			assertNotNull(revocation.getId());
		}
		assertTrue(Utils.isCollectionEmpty(signature.foundRevocations().getOrphanRevocationData()));

	}

	@Test
	public void testExtend() throws Exception {
		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		DSSDocument detachedContent = new FileDocument(DETACHED_DOC_PATH);
		parameters.setDetachedContents(Arrays.asList(detachedContent));
		FileDocument document = new FileDocument(SIGNED_DOC_PATH);
		Exception exception = assertThrows(DSSException.class, () -> service.extendDocument(document, parameters));
		assertEquals("Cryptographic signature verification has failed / Signature verification failed against the best candidate.",
				exception.getMessage());
	}

	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);

		assertEquals(1, signatures.size());
		AdvancedSignature advancedSignature = signatures.get(0);

		OfflineRevocationSource<CRL> crlSource = advancedSignature.getCRLSource();
		Set<EncapsulatedRevocationTokenIdentifier<CRL>> crlRevocationBinaries = crlSource.getAllReferencedRevocationBinaries();
		assertEquals(1, crlRevocationBinaries.size());

		try {
			String crlBinaries = "MIIDlDCCAXwCAQEwDQYJKoZIhvcNAQEFBQAwOzELMAkGA1UEBhMCRVMxETAPBgNVBAoMCEZOTVQtUkNNMRkwFwYDVQQLDBBBQyBSQUlaIEZOTVQtUkNNFw0xNDExMTgxMjExMjBaFw0xNTA1MTcxMTExMjBaoIIBCzCCAQcwCgYDVR0UBAMCARswHwYDVR0jBBgwFoAU933F/cTomht3ZKf1HaDMv4dgmm0wgdcGA1UdHAEB/wSBzDCByaCBw6CBwIaBkGxkYXA6Ly9sZGFwZm5tdC5jZXJ0LmZubXQuZXMvQ049Q1JMLE9VPUFDJTIwUkFJWiUyMEZOTVQtUkNNLE89Rk5NVC1SQ00sQz1FUz9hdXRob3JpdHlSZXZvY2F0aW9uTGlzdDtiaW5hcnk/YmFzZT9vYmplY3RjbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIYraHR0cDovL3d3dy5jZXJ0LmZubXQuZXMvY3Jscy9BUkxGTk1UUkNNLmNybIIB/zANBgkqhkiG9w0BAQUFAAOCAgEAgW8SisIJUr3HOPKb46fSA9jMq9tP5TBVESeBItPtYq3nkq9wXkTeegsRrglYEY4/Q4De73JqcZ5InuyhxMpukpHsMnRHZIKJLSbxGrqKwfqWbedP1mMqCC0XebeWrvFTfU0cdqC7d5IJ8nEcIIyUfKnKL5fNZrDeMBUfxiVmGbeBRSa2B+/tiAliCqI0QGZFqQof9rTDj1/7o6Cx0I+olKOQJ2S6l2/KyyzHpTiZJ9EVovrCLqLClkE8zRFjnqUn8DXDx6votB70mzsomJgRNwpSYjmI1wytFsKzQr5FcZCeqx3levclnDPJ8eZo12nv57frqYDU6ZOlZbggg6X6CiuVjENfLtK7OCcuJJdJlFY4aNVevUy6rRTiQsNUis4V/xewK+5sJDJAswuSc6xFxVBn7MBISHH7MMobvaOVP7/Sj0ZkJ9uaOHF7TQZaHZfCGuMUnQffnqhGOvwDnaQAtWOY+EM35SrPjz5abQO7XwKThuINueAsoKv3QyXcRKz8wJ3epK7fRVsL8gBIuZ7fdnDBKdbT+UTyVQZortRujSZhg02Hzx9ip4gbdVBmz0Dk7ebue3r2iNA6OztrRw7cQF54m7NcH/UJrOj1sO9iiJ5d+VG7RTj0Bl6/y8VEPk7B7HIW+jBeokb8ya/SlHyG1+MPHXjoOqMHtPY/djrQl4Y=";
			CRLBinary crlBinary = new CRLBinary(Utils.fromBase64(crlBinaries));
			Map<RevocationRef<CRL>, Set<RevocationRefOrigin>> crlRefs = crlSource.findRefsAndOriginsForBinary(crlBinary);
			assertEquals(1, crlRefs.size());

			RevocationRef<CRL> revocationRef = crlRefs.keySet().iterator().next();
			assertNotNull(crlSource.findBinaryForReference(revocationRef));
		} catch (Exception e) {
			fail("Unable to extract CRL Refs", e);
		}

		OfflineRevocationSource<OCSP> ocspSource = advancedSignature.getOCSPSource();
		Set<EncapsulatedRevocationTokenIdentifier<OCSP>> ocspRevocationBinaries = ocspSource.getAllReferencedRevocationBinaries();
		assertEquals(1, ocspRevocationBinaries.size());

		try {
			String ocspBinaries = "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";
			BasicOCSPResp basicOCSPResp = DSSRevocationUtils.loadOCSPBase64Encoded(ocspBinaries);
			OCSPResponseBinary ocspResponseBinary = OCSPResponseBinary.build(basicOCSPResp);
			Map<RevocationRef<OCSP>, Set<RevocationRefOrigin>> ocspRefs = ocspSource.findRefsAndOriginsForBinary(ocspResponseBinary);
			assertEquals(1, ocspSource.findRefsAndOriginsForBinary(ocspResponseBinary).size());

			RevocationRef<OCSP> revocationRef = ocspRefs.keySet().iterator().next();
			assertNotNull(ocspSource.findBinaryForReference(revocationRef));
		} catch (Exception e) {
			fail("Unable to extract OCSP Refs", e);
		}
	}

}
