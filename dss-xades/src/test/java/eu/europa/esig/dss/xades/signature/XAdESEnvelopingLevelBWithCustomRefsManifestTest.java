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
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;
import eu.europa.esig.dss.xades.reference.XPathTransform;
import org.apache.xml.security.transforms.Transforms;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESEnvelopingLevelBWithCustomRefsManifestTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private List<DSSDocument> detachedContents;

    @BeforeEach
    void init() throws Exception {
        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setManifestSignature(true);

        DSSDocument firstDocument = new FileDocument("src/test/resources/sample-c14n.xml");
        DSSDocument secondDocument = new FileDocument("src/test/resources/sample.xml");
        FileDocument thirdDocument = new FileDocument("src/test/resources/sampleWithPlaceOfSignature.xml");
        detachedContents = Arrays.asList(firstDocument, secondDocument, thirdDocument);

        DSSReference referenceOne = new DSSReference();
        referenceOne.setId("REF-ID1");
        referenceOne.setUri("sample-c14n.xml");
        referenceOne.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
        referenceOne.setContents(firstDocument);
        referenceOne.setTransforms(Arrays.asList(new XPathTransform("ancestor-or-self::*[@Id='dss1']")));

        DSSReference referenceTwo = new DSSReference();
        referenceTwo.setId("REF-ID2");
        referenceTwo.setUri("sample.xml");
        referenceTwo.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
        referenceTwo.setContents(secondDocument);
        referenceTwo.setTransforms(Arrays.asList(new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE)));

        DSSReference referenceThree = new DSSReference();
        referenceThree.setId("REF-ID3");
        referenceThree.setUri("sampleWithPlaceOfSignature.xml");
        referenceThree.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
        referenceThree.setContents(thirdDocument);
        referenceThree.setTransforms(Arrays.asList(new XPath2FilterTransform("//*[@id='data1']", "intersect"),
                new CanonicalizationTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)));

        ManifestBuilder manifestBuilder = new ManifestBuilder("manifest",
                Arrays.asList(referenceOne, referenceTwo, referenceThree));
        documentToSign = manifestBuilder.build();

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected void checkDigestMatchers(DiagnosticData diagnosticData) {
        super.checkDigestMatchers(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
        assertEquals(5, digestMatchers.size());

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
        assertEquals(3, manifestEntryCounter);
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
        assertEquals(4, signatureScopes.size());

        for (XmlSignatureScope signatureScope : signatureScopes) {
            assertNotNull(signatureScope.getSignerData());
            assertEquals(SignatureScopeType.FULL, signatureScope.getScope());
            assertNotNull(signatureScope.getName());
            assertNotNull(signatureScope.getDescription());
            assertTrue(Utils.isCollectionNotEmpty(signatureScope.getTransformations()));
        }
    }

    @Override
    public List<DSSDocument> getDetachedContents() {
        return detachedContents;
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
