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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XAdESLevelERSAddSignaturePolicyStoreTest extends AbstractXAdESTestValidation {

    private static final String SIGNATURE_POLICY_ID = "urn:sbr:signature-policy:xml:2.0";
    private static final DSSDocument POLICY_CONTENT = new FileDocument("src/test/resources/validation/dss2095/SBR-signature-policy-v2.0.xml");

    private XAdESService service;
    private DSSDocument signedDocument;

    @BeforeEach
    void init() throws Exception {
        service = new XAdESService(getOfflineCertificateVerifier());
        signedDocument = new FileDocument(new File("src/test/resources/validation/evidence-record/X-E-ERS-LT.xml"));
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return signedDocument;
    }

    @Test
    @Override
    public void validate() {
        SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
        signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);
        SpDocSpecification spDocSpec = new SpDocSpecification();
        spDocSpec.setId(SIGNATURE_POLICY_ID);
        signaturePolicyStore.setSpDocSpecification(spDocSpec);

        Exception exception = assertThrows(IllegalInputException.class, () -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
        assertEquals("Signature extension is not possible. The signature already contains en embedded evidence record.", exception.getMessage());
    }

}
