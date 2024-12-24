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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESWithSigPolDocLocalURITest extends AbstractXAdESTestSignature {

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";

    private static final String LOCAL_URI = "/local/path/policy.pdf";

    private static final DSSDocument POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());

    private XAdESService service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        Policy signaturePolicy = new Policy();
        signaturePolicy.setId("urn:oid:" + SIGNATURE_POLICY_ID);

        signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signaturePolicy.setDigestValue(DSSUtils.digest(DigestAlgorithm.SHA256, POLICY_CONTENT));
        signaturePolicy.setSpuri(HTTP_SPURI_TEST);

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        service = new XAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();

        SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
        SpDocSpecification spDocSpec = new SpDocSpecification();
        spDocSpec.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        signaturePolicyStore.setSpDocSpecification(spDocSpec);

        signaturePolicyStore.setSigPolDocLocalURI(LOCAL_URI);

        DSSDocument signedDocumentWithSignaturePolicyStore = service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
        assertNotNull(signedDocumentWithSignaturePolicyStore);

        return signedDocumentWithSignaturePolicyStore;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        String xmlContent = new String(byteArray);
        assertTrue(xmlContent.contains(HTTP_SPURI_TEST));

        assertTrue(xmlContent.contains(":SignaturePolicyStore"));
        assertTrue(xmlContent.contains(":SPDocSpecification"));
        assertTrue(xmlContent.contains(LOCAL_URI));
    }

    @Override
    protected SignaturePolicyProvider getSignaturePolicyProvider() {
        Map<String, DSSDocument> policyMapByUri = new HashMap<>();
        policyMapByUri.put(LOCAL_URI, POLICY_CONTENT);

        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        signaturePolicyProvider.setSignaturePoliciesByUrl(policyMapByUri);

        return signaturePolicyProvider;
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);
        assertEquals(1, signatures.size());

        XAdESSignature xadesSignature = (XAdESSignature) signatures.get(0);
        SignaturePolicyStore extractedSPS = xadesSignature.getSignaturePolicyStore();
        assertNotNull(extractedSPS);
        assertNotNull(extractedSPS.getSpDocSpecification());
        assertEquals(SIGNATURE_POLICY_ID, extractedSPS.getSpDocSpecification().getId());
        assertNull(extractedSPS.getSpDocSpecification().getDescription());
        assertEquals(LOCAL_URI, extractedSPS.getSigPolDocLocalURI());
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isPolicyPresent());

        assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());

        assertFalse(signature.isPolicyAsn1Processable());
        assertTrue(signature.isPolicyIdentified());
        assertTrue(signature.isPolicyDigestValid());
        assertTrue(signature.isPolicyDigestAlgorithmsEqual());
    }

    @Override
    protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyStore(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());
        assertEquals(LOCAL_URI, signature.getPolicyStoreLocalURI());
        assertNull(signature.getPolicyStoreDescription());
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
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

