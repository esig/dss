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

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESLevelBCounterSignatureWithNonB64Test extends AbstractJAdESCounterSignatureTest {

    private JAdESService service;
    private DSSDocument documentToSign;

    private JAdESSignatureParameters signatureParameters;
    private JAdESCounterSignatureParameters counterSignatureParameters;

    private Date signingDate;

    @BeforeEach
    public void init() throws Exception {
        service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
        signingDate = new Date();

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

        counterSignatureParameters = new JAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(signingDate);
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        counterSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        counterSignatureParameters.setBase64UrlEncodedPayload(false);
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected JAdESCounterSignatureParameters getCounterSignatureParameters() {
        return counterSignatureParameters;
    }

    @Override
    protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
        Exception exception = assertThrows(IllegalInputException.class, () -> super.counterSign(signatureDocument, signatureId));
        assertEquals("The payload contains not URL-safe characters! " +
                "With Unencoded Payload ('b64' = false) only ASCII characters in ranges " +
                "%x20-2D and %x2F-7E are allowed for a COMPACT_SERIALIZATION!", exception.getMessage());

        counterSignatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

        exception = assertThrows(IllegalInputException.class, () -> super.counterSign(signatureDocument, signatureId));
        assertEquals("The payload contains not valid content! " +
                "With Unencoded Payload ('b64' = false) only UTF-8 characters are allowed!", exception.getMessage());

        counterSignatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        return super.counterSign(signatureDocument, signatureId);
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(new InMemoryDocument(byteArray));
        assertTrue(jwsJsonSerializationParser.isSupported());

        JWSJsonSerializationObject jsonSerializationObject = jwsJsonSerializationParser.parse();
        List<JWS> jwsSignatures = jsonSerializationObject.getSignatures();
        assertEquals(1, jwsSignatures.size());

        JWS jws = jwsSignatures.iterator().next();
        List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
        assertEquals(1, etsiU.size());

        Map<String, Object> item = DSSJsonUtils.parseEtsiUComponent(etsiU.iterator().next());
        assertEquals(1, item.size());

        Map<String, Object> cSig = (Map<String, Object>) item.get(JAdESHeaderParameterNames.C_SIG);
        assertNotNull(cSig);

        assertNull(cSig.get(JWSConstants.PAYLOAD));
        assertNotNull(cSig.get(JWSConstants.PROTECTED));
        assertNotNull(cSig.get(JWSConstants.SIGNATURE));
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
    protected CounterSignatureService<JAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
