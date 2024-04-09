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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.JWSConverter;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class JAdESLevelBDetachedUriByHashNonB64Test extends AbstractJAdESTestSignature {

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private DSSDocument documentToSign;
    private Date signingDate;

    @BeforeEach
    public void init() throws Exception {
        service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
        signingDate = new Date();
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setBase64UrlEncodedPayload(false);
        return signatureParameters;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        InMemoryDocument compactSignature = new InMemoryDocument(byteArray);
        JWSCompactSerializationParser parser = new JWSCompactSerializationParser(compactSignature);
        JWS jws = parser.parse();
        assertNotNull(jws);

        assertRequirementsValid(jws.getEncodedHeader());

        DSSDocument converted = JWSConverter.fromJWSCompactToJSONFlattenedSerialization(compactSignature);
        assertNotNull(converted);
        assertNotNull(converted.getMimeType());
        assertNotNull(converted.getName());

        verify(converted);

        converted = JWSConverter.fromJWSCompactToJSONSerialization(compactSignature);
        assertNotNull(converted);
        assertNotNull(converted.getMimeType());
        assertNotNull(converted.getName());

        verify(converted);
    }

    private void assertRequirementsValid(String encodedHeader) {
        try {
            String jsonString = new String(DSSJsonUtils.fromBase64Url(encodedHeader));
            Map<String, Object> protectedHeaderMap = JsonUtil.parseJson(jsonString);

            Object cty = protectedHeaderMap.get(HeaderParameterNames.CONTENT_TYPE);
            assertNull(cty);

            Map<?, ?> sigD = (Map<?, ?>) protectedHeaderMap.get(JAdESHeaderParameterNames.SIG_D);
            assertNotNull(sigD);

            Object mId = sigD.get(JAdESHeaderParameterNames.M_ID);
            assertNotNull(mId);

            String hashM = (String) sigD.get(JAdESHeaderParameterNames.HASH_M);
            assertNotNull(hashM);
            DigestAlgorithm digestAlgorithm = DigestAlgorithm.forJAdES(hashM);
            assertNotNull(digestAlgorithm);

            List<?> pars = (List<?>) sigD.get(JAdESHeaderParameterNames.PARS);
            assertTrue(Utils.isCollectionNotEmpty(pars));

            List<?> hashV = (List<?>) sigD.get(JAdESHeaderParameterNames.HASH_V);
            assertTrue(Utils.isCollectionNotEmpty(hashV));
            assertEquals(1, hashV.size());
            assertEquals(DSSJsonUtils.toBase64Url(DSSUtils.digest(digestAlgorithm, documentToSign)), hashV.get(0));

            List<?> ctys = (List<?>) sigD.get(JAdESHeaderParameterNames.CTYS);
            assertTrue(Utils.isCollectionNotEmpty(ctys));

            assertEquals(pars.size(), hashV.size());
            assertEquals(pars.size(), ctys.size());

            Boolean b64 = (Boolean) protectedHeaderMap.get(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
            assertNotNull(b64);
            assertFalse(b64);

        } catch (JoseException e) {
            fail(e);
        }
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(documentToSign);
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        assertEquals(1, diagnosticData.getOriginalSignerDocuments().size());

        SignerDataWrapper signerData = diagnosticData.getOriginalSignerDocuments().get(0);
        XmlDigestAlgoAndValue digestAlgoAndValue = signerData.getDigestAlgoAndValue();
        assertNotNull(digestAlgoAndValue);

        assertArrayEquals(documentToSign.getDigestValue(digestAlgoAndValue.getDigestMethod()), digestAlgoAndValue.getDigestValue());
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
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
