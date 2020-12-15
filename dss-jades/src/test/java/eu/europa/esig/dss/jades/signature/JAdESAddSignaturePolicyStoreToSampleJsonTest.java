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

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JAdESAddSignaturePolicyStoreToSampleJsonTest extends AbstractJAdESTestSignature {

    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
    private static final DSSDocument SIGNATURE_POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());
    private static final String[] DOCUMENTATION_REFERENCES = new String[] { "http://docref.com/ref1", "http://docref.com/ref2" };

    private JAdESService service;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() {
        service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
    }

    @Test
    public void test() {
        SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
        signaturePolicyStore.setSignaturePolicyContent(SIGNATURE_POLICY_CONTENT);
        SpDocSpecification spDocSpec = new SpDocSpecification();
        spDocSpec.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        spDocSpec.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        spDocSpec.setDocumentationReferences(DOCUMENTATION_REFERENCES);
        signaturePolicyStore.setSpDocSpecification(spDocSpec);

        Exception exception = assertThrows(DSSException.class, () ->
                service.addSignaturePolicyStore(documentToSign, signaturePolicyStore));
        assertEquals("There is no signature to extend!", exception.getMessage());
    }

    @Override
    public void signAndVerify() {
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
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
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
