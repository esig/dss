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
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESWithASN1PolicyWithDigPSpFailureTest extends AbstractJAdESTestSignature {

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
    private static final String SIGNATURE_POLICY_DOCUMENTATION = "http://nowina.lu/signature-policy.der";

    private static final DSSDocument POLICY_CONTENT = new FileDocument("src/test/resources/validation/signature-policy.der");

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private JAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample.json");

        Policy signaturePolicy = new Policy();
        signaturePolicy.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        signaturePolicy.setSpuri(HTTP_SPURI_TEST);
        signaturePolicy.setHashAsInTechnicalSpecification(true);

        byte[] base64Digest = POLICY_CONTENT.getDigestValue(DigestAlgorithm.SHA256);
        signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signaturePolicy.setDigestValue(base64Digest);

        SpDocSpecification spDocSpecification = new SpDocSpecification();
        spDocSpecification.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        spDocSpecification.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        spDocSpecification.setDocumentationReferences(SIGNATURE_POLICY_DOCUMENTATION);
        signaturePolicy.setSpDocSpecification(spDocSpecification);

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);

        service = new JAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected SignaturePolicyProvider getSignaturePolicyProvider() {
        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<>();
        signaturePoliciesByUrl.put(HTTP_SPURI_TEST, POLICY_CONTENT);
        signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
        return signaturePolicyProvider;
    }

    @Override
    protected void checkSignaturePolicy(List<AdvancedSignature> signatures) {
        super.checkSignaturePolicy(signatures);

        assertEquals(1, signatures.size());
        AdvancedSignature advancedSignature = signatures.get(0);

        SignaturePolicy signaturePolicy = advancedSignature.getSignaturePolicy();
        assertNotNull(signaturePolicy);
        assertEquals(SIGNATURE_POLICY_ID, signaturePolicy.getIdentifier());
        assertEquals(HTTP_SPURI_TEST, signaturePolicy.getUri());
        assertTrue(signaturePolicy.isHashAsInTechnicalSpecification());
        assertNotNull(signaturePolicy.getDocSpecification());
        assertEquals(SIGNATURE_POLICY_ID, signaturePolicy.getDocSpecification().getId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signaturePolicy.getDocSpecification().getDescription());
        assertEquals(SIGNATURE_POLICY_DOCUMENTATION, signaturePolicy.getDocSpecification().getDocumentationReferences()[0]);
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isPolicyPresent());
        assertTrue(signature.isPolicyIdentified());
        assertTrue(signature.isPolicyDigestAlgorithmsEqual());
        assertTrue(signature.isPolicyAsn1Processable()); // processed as binary content
        assertFalse(signature.isPolicyDigestValid());
        assertFalse(Utils.isStringEmpty(signature.getPolicyProcessingError()));
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
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
