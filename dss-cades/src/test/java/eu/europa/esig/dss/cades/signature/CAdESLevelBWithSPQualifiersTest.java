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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSPDocSpecification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlUserNotice;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CAdESLevelBWithSPQualifiersTest extends AbstractCAdESTestSignature {

    private static final String HELLO_WORLD = "Hello World";

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final String SIGNATURE_POLICY_ORGANIZATION = "Nowina Solutions";
    private static final int[] SIGNATURE_POLICY_NOTICE_NUMBERS = new int[] { 1, 2, 3, 4 };
    private static final String SIGNATURE_POLICY_EXPLICIT_TEXT = "This is the internal signature policy";

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());

        Policy signaturePolicy = new Policy();
        signaturePolicy.setId(SIGNATURE_POLICY_ID);
        signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA1);
        signaturePolicy.setDigestValue(new byte[] { 'd', 'i', 'g', 'e', 's', 't', 'v', 'a', 'l', 'u', 'e' });
        signaturePolicy.setSpuri(HTTP_SPURI_TEST);

        UserNotice userNotice = new UserNotice();
        userNotice.setOrganization(SIGNATURE_POLICY_ORGANIZATION);
        userNotice.setNoticeNumbers(SIGNATURE_POLICY_NOTICE_NUMBERS);
        userNotice.setExplicitText(SIGNATURE_POLICY_EXPLICIT_TEXT);
        signaturePolicy.setUserNotice(userNotice);

        SpDocSpecification spDocSpecification = new SpDocSpecification();
        spDocSpecification.setId(SIGNATURE_POLICY_ID);
        signaturePolicy.setSpDocSpecification(spDocSpecification);

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

        service = new CAdESService(getOfflineCertificateVerifier());

    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());

        XmlUserNotice userNotice = signature.getPolicyUserNotice();
        assertNotNull(userNotice);
        assertEquals(SIGNATURE_POLICY_ORGANIZATION, userNotice.getOrganization());
        assertEquals(DSSUtils.toBigIntegerList(SIGNATURE_POLICY_NOTICE_NUMBERS), userNotice.getNoticeNumbers());
        assertEquals(SIGNATURE_POLICY_EXPLICIT_TEXT, userNotice.getExplicitText());

        XmlSPDocSpecification spDocSpecification = signature.getPolicyDocSpecification();
        assertNotNull(spDocSpecification);
        assertEquals(SIGNATURE_POLICY_ID, spDocSpecification.getId());
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
