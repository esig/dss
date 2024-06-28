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
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.DSSObject;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESEnvelopedLevelBWithManifestTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private DSSDocument manifest;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA512);

        DSSReference envelopedManifestReference = new DSSReference();
        envelopedManifestReference.setId("r-enveloped");
        envelopedManifestReference.setUri("");
        envelopedManifestReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
        envelopedManifestReference.setContents(documentToSign);
        envelopedManifestReference.setTransforms(Arrays.asList(new EnvelopedSignatureTransform(),
                new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE)));

        ManifestBuilder manifestBuilder = new ManifestBuilder("manifest", Arrays.asList(envelopedManifestReference));
        manifest = manifestBuilder.build();

        DSSReference manifestReference = new DSSReference();
        manifestReference.setId("r-manifest");
        manifestReference.setType("http://www.w3.org/2000/09/xmldsig#Manifest");
        manifestReference.setUri("#manifest");
        manifestReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
        manifestReference.setContents(manifest);
        manifestReference.setTransforms(Arrays.asList(new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE)));

        signatureParameters.setReferences(Arrays.asList(manifestReference));

        DSSObject object = new DSSObject();
        object.setContent(manifest);
        signatureParameters.setObjects(Arrays.asList(object));

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();

        // in order to extract original document correctly
        documentToSign = manifest;

        return signedDocument;
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
        assertEquals(3, digestMatchers.size());

        int manifestCounter = 0;
        int manifestEntryCounter = 0;
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            assertTrue(digestMatcher.isDataFound());
            assertTrue(digestMatcher.isDataIntact());
            if (DigestMatcherType.MANIFEST.equals(digestMatcher.getType())) {
                ++manifestCounter;
            } else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                ++manifestEntryCounter;
            }
        }
        assertEquals(1, manifestCounter);
        assertEquals(1, manifestEntryCounter);
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
        assertEquals(2, signatureScopes.size());

        boolean manifestRefFound = false;
        boolean envelopedRefFound = false;
        for (XmlSignatureScope signatureScope : signatureScopes) {
            assertNotNull(signatureScope.getSignerData());
            assertEquals(SignatureScopeType.FULL, signatureScope.getScope());
            assertNotNull(signatureScope.getDescription());
            if ("r-manifest".equals(signatureScope.getName())) {
                assertEquals(1, signatureScope.getTransformations().size());
                manifestRefFound = true;
            } else if ("r-enveloped".equals(signatureScope.getName())) {
                assertEquals(2, signatureScope.getTransformations().size());
                envelopedRefFound = true;
            }
        }
        assertTrue(manifestRefFound);
        assertTrue(envelopedRefFound);
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
