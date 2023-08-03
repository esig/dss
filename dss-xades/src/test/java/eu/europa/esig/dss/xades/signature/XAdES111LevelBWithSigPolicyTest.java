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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.xades.definition.XAdESNamespaces;
import eu.europa.esig.xades.XAdES111Utils;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class XAdES111LevelBWithSigPolicyTest extends AbstractXAdESTestSignature {

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
    private static final String SIGNATURE_POLICY_DOCUMENTATION = "http://nowina.lu/signature-policy.pdf";

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument("Hello world".getBytes(), "test+file.txt");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setXadesNamespace(XAdESNamespaces.XADES_111);
        signatureParameters.setEn319132(false);

        Policy signaturePolicy = new Policy();
        signaturePolicy.setId(SIGNATURE_POLICY_ID);
        signaturePolicy.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        signaturePolicy.setDocumentationReferences(SIGNATURE_POLICY_DOCUMENTATION, Utils.EMPTY_STRING); // empty is permitted as URI
        signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA1);
        signaturePolicy.setDigestValue(new byte[]{'d', 'i', 'g', 'e', 's', 't', 'v', 'a', 'l', 'u', 'e'});
        signaturePolicy.setSpuri(HTTP_SPURI_TEST);
        signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        try (InputStream is = new ByteArrayInputStream(byteArray)) {
            List<String> errorMessages = XAdES111Utils.getInstance().validateAgainstXSD(new StreamSource(is));
            assertTrue(Utils.isCollectionEmpty(errorMessages), "Unable to validate against the XSD : " + errorMessages);
        } catch (IOException e) {
            fail("Unable to read the signed document : " + e.getMessage());
        }
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyDescription());
        assertEquals(SIGNATURE_POLICY_DOCUMENTATION, signature.getPolicyDocumentationReferences().get(0));
        assertEquals(Utils.EMPTY_STRING, signature.getPolicyDocumentationReferences().get(1));
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
