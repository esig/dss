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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.x509.SignaturePolicy;
import org.junit.Test;

import java.io.File;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class XAdESValidationTest {

    private static final String POLICY_ID = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
    private static final String POLICY_URL = "http://spuri.test";
    private static final String POLICY_DIGEST_VALUE = "3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs=";

    @Test
    public void validatedXadesSignatureShouldContainPolicyParameters() throws Exception {
        XAdESSignature xadesSignature = openXadesSignature("src/test/resources/validation/valid-xades.xml");
        SignaturePolicy policy = xadesSignature.getPolicyId();
        assertEquals(POLICY_ID, policy.getIdentifier());
        assertEquals(DigestAlgorithm.SHA256, policy.getDigestAlgorithm());
        assertEquals(POLICY_DIGEST_VALUE, policy.getDigestValue());
        assertEquals(POLICY_URL, policy.getUrl());
    }

    private XAdESSignature openXadesSignature(String documentPath) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(new File(documentPath)));
        List<AdvancedSignature> signatureList = validator.getSignatures();
        return (XAdESSignature) signatureList.get(0);
    }
}
