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
package eu.europa.esig.dss.jades.requirements;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.signature.AbstractJAdESTestSignature;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractJAdESRequirementsCheck extends AbstractJAdESTestSignature {
	
	private JAdESService service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;
	
	@BeforeEach
	void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		
		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
	}
	
	@Override
	protected void onDocumentSigned(byte[] byteArray)  {
		super.onDocumentSigned(byteArray);
		
		try {
			String payload = getPayload(byteArray);
			checkPayload(payload);
			
			String protectedHeader = getProtectedHeader(byteArray);
			checkProtectedHeader(protectedHeader);
			
			String signatureValue = getSignatureValue(byteArray);
			checkSignatureValue(signatureValue);
			
			Map<?, ?> unprotectedHeader = getUnprotectedHeader(byteArray);
			checkUnprotectedHeader(unprotectedHeader);
			
		} catch (Exception e) {
			fail(e);
		}
	}

	protected abstract String getPayload(byte[] byteArray) throws Exception;
	
	protected abstract String getProtectedHeader(byte[] byteArray) throws Exception;
	
	protected abstract String getSignatureValue(byte[] byteArray) throws Exception;
	
	protected abstract Map<?, ?> getUnprotectedHeader(byte[] byteArray) throws Exception;
	
	protected void checkPayload(String payload) {
		assertNotNull(payload);
		assertTrue(DSSJsonUtils.isBase64UrlEncoded(payload));
	}
	
	protected void checkProtectedHeader(String protectedHeader) throws Exception {
		assertNotNull(protectedHeader);
		assertTrue(DSSJsonUtils.isBase64UrlEncoded(protectedHeader));
		
		String jsonString = new String(DSSJsonUtils.fromBase64Url(protectedHeader));
		Map<String, Object> protectedHeaderMap = JsonUtil.parseJson(jsonString);
		
		checkSigningCertificate(protectedHeaderMap);
		checkCertificateChain(protectedHeaderMap);
		checkSigningTime(protectedHeaderMap);
		checkContentType(protectedHeaderMap);
		checkCrit(protectedHeaderMap);
	}

	@SuppressWarnings("unchecked")
	protected void checkSigningCertificate(Map<?, ?> protectedHeaderMap) {
		Object x5tNS256 = protectedHeaderMap.get(HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT);
		Object x5tNo = protectedHeaderMap.get("x5t#o");
		assertTrue(x5tNS256 != null ^ x5tNo != null);

		if (x5tNS256 != null) {
			assertTrue(DSSJsonUtils.isBase64UrlEncoded((String) x5tNS256));
		}

		if (x5tNo != null) {
			Map<String, Object> x5tNoMap = (Map<String, Object>) x5tNo;
			String digAlg = (String) x5tNoMap.get("digAlg");
			assertNotNull(digAlg);
			DigestAlgorithm digestAlgorithm = DigestAlgorithm.forJAdES(digAlg);
			assertNotNull(digestAlgorithm);
			assertNotEquals(DigestAlgorithm.SHA256, digestAlgorithm);

			assertTrue(DSSJsonUtils.isBase64UrlEncoded((String) x5tNoMap.get("digVal")));
		}

		Object sigX5ts = protectedHeaderMap.get("sigX5ts");
		assertNull(sigX5ts);
	}

	private void checkCertificateChain(Map<String, Object> protectedHeaderMap) {
		List<?> x5c = (List<?>) protectedHeaderMap.get(HeaderParameterNames.X509_CERTIFICATE_CHAIN);
		assertTrue(Utils.isCollectionNotEmpty(x5c));
		for (Object certObject : x5c) {
			assertNotNull(certObject);
			assertTrue(certObject instanceof String);
			assertTrue(Utils.isBase64Encoded((String) certObject));
			CertificateToken certificateToken = DSSUtils.loadCertificateFromBase64EncodedString((String) certObject);
			assertNotNull(certificateToken);
		}
	}

	protected void checkSigningTime(Map<String, Object> protectedHeaderMap) throws Exception {
		String sigT = (String) protectedHeaderMap.get("sigT");
		assertNull(sigT);

		Number iat = (Number) protectedHeaderMap.get("iat");
		Date date = new Date(iat.longValue() * 1000L);
		assertNotNull(date);
		assertEquals(signatureParameters.bLevel().getSigningDate().getTime() / 1000L, iat.longValue());
	}

	protected void checkContentType(Map<String, Object> protectedHeaderMap) {
		Object cty = protectedHeaderMap.get(HeaderParameterNames.CONTENT_TYPE);
		Object sigD = protectedHeaderMap.get("sigD");
		assertTrue(cty != null ^ sigD != null);
	}

	private void checkCrit(Map<String, Object> protectedHeaderMap) {
		List<String> excludedHeaders = Arrays.asList(HeaderParameterNames.AGREEMENT_PARTY_U_INFO, HeaderParameterNames.AGREEMENT_PARTY_V_INFO,
				HeaderParameterNames.ALGORITHM, HeaderParameterNames.AUTHENTICATION_TAG, HeaderParameterNames.CONTENT_TYPE, HeaderParameterNames.CRITICAL, 
				HeaderParameterNames.ENCRYPTION_METHOD, HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, HeaderParameterNames.INITIALIZATION_VECTOR, 
				HeaderParameterNames.JWK, HeaderParameterNames.JWK_SET_URL, HeaderParameterNames.KEY_ID, HeaderParameterNames.PBES2_ITERATION_COUNT, 
				HeaderParameterNames.PBES2_SALT_INPUT, HeaderParameterNames.TYPE, HeaderParameterNames.X509_CERTIFICATE_CHAIN, 
				HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT, HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT, HeaderParameterNames.X509_URL, 
				HeaderParameterNames.ZIP, JAdESHeaderParameterNames.ETSI_U);
		
		List<String> includedHeaders = Arrays.asList(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, "sigD");

		List<String> presentHeaders = new ArrayList<>();
		for (String protectedHeaderKey : protectedHeaderMap.keySet()) {
			if (includedHeaders.contains(protectedHeaderKey)) {
				presentHeaders.add(protectedHeaderKey);
			}
		}

		List<?> crit = (List<?>) protectedHeaderMap.get(HeaderParameterNames.CRITICAL);
		if (Utils.isCollectionNotEmpty(presentHeaders)) {
			assertTrue(Utils.isCollectionNotEmpty(crit));

			for (Object critEntry : crit) {
				assertNotNull(critEntry);
				assertInstanceOf(String.class, critEntry);
				assertFalse(excludedHeaders.contains(critEntry));
				assertTrue(includedHeaders.contains(critEntry));
			}
		}
	}

	protected void checkSignatureValue(String signatureValue) {
		assertNotNull(signatureValue);
		assertTrue(DSSJsonUtils.isBase64UrlEncoded(signatureValue));
	}
	
	protected void checkUnprotectedHeader(Map<?, ?> unprotectedHeaderMap) throws Exception {	
		checkSignatureTimestamp(unprotectedHeaderMap);
		checkCertificateValues(unprotectedHeaderMap);
		checkRevocationValues(unprotectedHeaderMap);
		checkCertificateReferences(unprotectedHeaderMap);
		checkRevocationReferences(unprotectedHeaderMap);
		checkRefTimestamps(unprotectedHeaderMap);
		checkTstValidationData(unprotectedHeaderMap);
		checkAnyValidationData(unprotectedHeaderMap);
		checkArchiveTimestamp(unprotectedHeaderMap);
	}

	protected void checkSignatureTimestamp(Map<?, ?> unprotectedHeaderMap) {
		Map<?, ?> sigTst = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "sigTst");
		assertNotNull(sigTst);
		assertNull(sigTst.get("canonAlg"));
		List<?> tstTokens = (List<?>) sigTst.get("tstTokens");
		assertNotNull(tstTokens);
		assertEquals(1, tstTokens.size());
	}

	protected void checkCertificateValues(Map<?, ?> unprotectedHeaderMap) {
		List<?> xVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "xVals");
		assertTrue(Utils.isCollectionNotEmpty(xVals));
		assertCertValsValid(xVals);
		
		List<?> axVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "axVals");
		if (axVals != null) {
			assertCertValsValid(axVals);
		}
	}
	
	private void assertCertValsValid(List<?> vals) {
		List<Object> pkiObjects = new ArrayList<>();
		for (Object xVal : vals) {
			assertNotNull(xVal);
			assertTrue(xVal instanceof Map<?, ?>);
			Object x509Cert = ((Map<?, ?>) xVal).get("x509Cert");
			assertNotNull(x509Cert);
			pkiObjects.add(x509Cert);
		}
		assertTrue(Utils.isCollectionNotEmpty(pkiObjects));
		assertNoDuplicatesFound(pkiObjects);
	}

	protected void checkRevocationValues(Map<?, ?> unprotectedHeaderMap) {
		Map<?, ?> rVals = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "rVals");
		assertTrue(Utils.isMapNotEmpty(rVals));
		assertRevValsValid(rVals);
		
		List<?> arVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "arVals");
		assertNull(arVals);
	}

	private void assertRevValsValid(Map<?, ?> rVals) {
		List<?> crlVals = (List<?>) rVals.get("crlVals");
		assertTrue(Utils.isCollectionNotEmpty(crlVals));
		assertNoDuplicatesFound(crlVals);
		
		List<?> ocspVals = (List<?>) rVals.get("ocspVals");
		assertTrue(Utils.isCollectionNotEmpty(ocspVals));
		assertNoDuplicatesFound(ocspVals);
	}
	
	private void assertNoDuplicatesFound(List<?> pkiObjects) {
		List<String> valsList = new ArrayList<>();
		for (Object pkiOb : pkiObjects) {
			assertNotNull(pkiOb);
			assertTrue(pkiOb instanceof Map<?, ?>);
			Map<?, ?> pkiObMap = (Map<?, ?>) pkiOb;
			String val = (String) pkiObMap.get("val");
			assertNotNull(val);
			assertTrue(Utils.isBase64Encoded(val));
			assertFalse(valsList.contains(val));
			valsList.add(val);
		}
	}

	protected void checkCertificateReferences(Map<?, ?> unprotectedHeaderMap) {
		Object xRefs = getEtsiUElement(unprotectedHeaderMap, "xRefs");
		assertNull(xRefs);
		Object axRefs = getEtsiUElement(unprotectedHeaderMap, "axRefs");
		assertNull(axRefs);
	}

	protected void checkRevocationReferences(Map<?, ?> unprotectedHeaderMap) {
		Object rRefs = getEtsiUElement(unprotectedHeaderMap, "rRefs");
		assertNull(rRefs);
		Object arRefs = getEtsiUElement(unprotectedHeaderMap, "arRefs");
		assertNull(arRefs);
	}
	
	protected void checkRefTimestamps(Map<?, ?> unprotectedHeaderMap) {
		Object sigRTst = getEtsiUElement(unprotectedHeaderMap, "sigRTst");
		assertNull(sigRTst);
		Object rfsTst = getEtsiUElement(unprotectedHeaderMap, "rfsTst");
		assertNull(rfsTst);
	}

	protected void checkArchiveTimestamp(Map<?, ?> unprotectedHeaderMap) {
		Map<?, ?> arcTst = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "arcTst");
		assertNotNull(arcTst);
		
		List<?> tstTokens = (List<?>) arcTst.get("tstTokens");
		assertTrue(Utils.isCollectionNotEmpty(tstTokens));
	}

	protected void checkTstValidationData(Map<?, ?> unprotectedHeaderMap) {
		Map<?, ?> tstVD = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "tstVD");
		assertNotNull(tstVD);

		boolean xOrRValsFound = false;
		List<?> xVals = (List<?>) tstVD.get("xVals");
		if (Utils.isCollectionNotEmpty(xVals)) {
			assertCertValsValid(xVals);
			xOrRValsFound = true;
		}

		Map<?, ?> rVals = (Map<?, ?>) tstVD.get("rVals");
		if (Utils.isMapNotEmpty(rVals)) {
			assertRevValsValid(rVals);
			xOrRValsFound = true;
		}
		assertTrue(xOrRValsFound);
	}

	protected void checkAnyValidationData(Map<?, ?> unprotectedHeaderMap) {
		Map<?, ?> anyVD = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "anyValData");
		assertNotNull(anyVD);

		boolean xOrRValsFound = false;
		List<?> xVals = (List<?>) anyVD.get("xVals");
		if (Utils.isCollectionNotEmpty(xVals)) {
			assertCertValsValid(xVals);
			xOrRValsFound = true;
		}

		Map<?, ?> rVals = (Map<?, ?>) anyVD.get("rVals");
		if (Utils.isMapNotEmpty(rVals)) {
			assertRevValsValid(rVals);
			xOrRValsFound = true;
		}
		assertTrue(xOrRValsFound);
	}
	
	@SuppressWarnings("unchecked")
	protected Object getEtsiUElement(Map<?, ?> unprotectedHeaderMap, String headerName) {
		List<?> etsiU = (List<?>) unprotectedHeaderMap.get("etsiU");
		for (Object etsiUItem : etsiU) {
			Map<String, Object> map = null;
			if (etsiUItem instanceof String) {
				byte[] decoded = Base64Url.decode((String) etsiUItem);
				try {
					map = JsonUtil.parseJson(new String(decoded));
				} catch (JoseException e) {
					fail("Unable to parse an 'etsiU' element : " + e.getMessage());
				}
			} else if (etsiUItem instanceof Map) {
				map = (Map<String, Object>) etsiUItem;
			}
			if (map == null) {
				fail("An etsiU component of a valid type is not found!");
			}
			Object object = map.get(headerName);
			if (object != null) {
				return object;
			}
		}
		return null;
	}
	
	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}
	
	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
