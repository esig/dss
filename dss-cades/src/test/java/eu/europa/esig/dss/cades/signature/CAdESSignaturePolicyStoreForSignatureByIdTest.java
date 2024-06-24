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
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
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
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESSignaturePolicyStoreForSignatureByIdTest extends AbstractCAdESTestSignature {

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";

    private static final DSSDocument POLICY_CONTENT = new FileDocument("src/test/resources/validation/signature-policy.der");

    private CAdESService service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private static final DSSDocument ORIGINAL_DOCUMENT = new InMemoryDocument("Hello World!".getBytes());

    @BeforeEach
    public void init() throws Exception {
        documentToSign = ORIGINAL_DOCUMENT;

        Policy signaturePolicy = new Policy();
        signaturePolicy.setId(SIGNATURE_POLICY_ID);

        signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signaturePolicy.setDigestValue(Utils.fromBase64("UB1ptLcfxuVzI8LHQTGpyMYkCb43i6eI3CiFVWEbnlg="));
        signaturePolicy.setSpuri(HTTP_SPURI_TEST);

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

        service = new CAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();

        SignedDocumentValidator validator = getValidator(signedDocument);
        String firstSigId = validator.getSignatures().get(0).getId();

        documentToSign = signedDocument;

        signatureParameters.bLevel().setSigningDate(new Date());
        DSSDocument doubleSignedDocument = super.sign();

        SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
        SpDocSpecification spDocSpec = new SpDocSpecification();
        spDocSpec.setId(SIGNATURE_POLICY_ID);
        signaturePolicyStore.setSpDocSpecification(spDocSpec);
        signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);

        CAdESSignaturePolicyStoreBuilder signaturePolicyStoreBuilder = new CAdESSignaturePolicyStoreBuilder();
        DSSDocument signedDocumentWithSignaturePolicyStore = signaturePolicyStoreBuilder.addSignaturePolicyStore(
                doubleSignedDocument, signaturePolicyStore, firstSigId);
        assertNotNull(signedDocumentWithSignaturePolicyStore);
        signedDocumentWithSignaturePolicyStore.setName("signature-with-sps.p7m");

        documentToSign = ORIGINAL_DOCUMENT;

        return signedDocumentWithSignaturePolicyStore;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        boolean signatureWithPolStoreFound = false;
        boolean signatureWithoutPolStoreFound = false;
        for (AdvancedSignature signature : signatures) {
            CAdESSignature CAdESSignature = (CAdESSignature) signature;
            SignaturePolicyStore extractedSPS = CAdESSignature.getSignaturePolicyStore();
            if (extractedSPS != null) {
                assertNotNull(extractedSPS.getSpDocSpecification());
                assertEquals(SIGNATURE_POLICY_ID, extractedSPS.getSpDocSpecification().getId());
                assertNull(extractedSPS.getSpDocSpecification().getDescription());
                assertArrayEquals(DSSUtils.toByteArray(POLICY_CONTENT), DSSUtils.toByteArray(extractedSPS.getSignaturePolicyContent()));
                signatureWithPolStoreFound = true;
            } else {
                signatureWithoutPolStoreFound = true;
            }
        }
        assertTrue(signatureWithPolStoreFound);
        assertTrue(signatureWithoutPolStoreFound);
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        boolean signatureWithPolStoreFound = false;
        boolean signatureWithoutPolStoreFound = false;
        for (String signatureId : diagnosticData.getSignatureIdList()) {
            SignatureWrapper signature = diagnosticData.getSignatureById(signatureId);
            assertTrue(signature.isPolicyPresent());

            assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
            assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());

            if (signature.isPolicyIdentified()) {
                assertTrue(signature.isPolicyAsn1Processable());
                assertTrue(signature.isPolicyDigestValid());
                assertTrue(signature.isPolicyDigestAlgorithmsEqual());
                signatureWithPolStoreFound = true;
            } else {
                signatureWithoutPolStoreFound = true;
            }
        }
        assertTrue(signatureWithPolStoreFound);
        assertTrue(signatureWithoutPolStoreFound);
    }

    @Override
    protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyStore(diagnosticData);

        boolean signatureWithPolStoreFound = false;
        boolean signatureWithoutPolStoreFound = false;
        for (String signatureId : diagnosticData.getSignatureIdList()) {
            SignatureWrapper signature = diagnosticData.getSignatureById(signatureId);
            if (signature.isPolicyStorePresent()) {
                assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());

                XmlDigestAlgoAndValue policyStoreDigestAlgoAndValue = signature.getPolicyStoreDigestAlgoAndValue();
                assertNotNull(policyStoreDigestAlgoAndValue);
                assertNotNull(signature.getPolicyStoreDigestAlgoAndValue().getDigestMethod());
                assertTrue(Utils.isArrayNotEmpty(policyStoreDigestAlgoAndValue.getDigestValue()));

                XmlDigestAlgoAndValue policyDigestAlgoAndValue = signature.getPolicyDigestAlgoAndValue();
                assertEquals(policyDigestAlgoAndValue.getDigestMethod(), policyStoreDigestAlgoAndValue.getDigestMethod());
                assertArrayEquals(policyDigestAlgoAndValue.getDigestValue(), policyStoreDigestAlgoAndValue.getDigestValue());

                signatureWithPolStoreFound = true;

            } else {
                signatureWithoutPolStoreFound = true;
            }
        }
        assertTrue(signatureWithPolStoreFound);
        assertTrue(signatureWithoutPolStoreFound);
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
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