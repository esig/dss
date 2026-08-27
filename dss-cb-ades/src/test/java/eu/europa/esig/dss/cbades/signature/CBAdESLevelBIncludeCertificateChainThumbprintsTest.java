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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.cbades.COSEConstants;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSESign;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.KidCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBIncludeCertificateChainThumbprintsTest extends AbstractCBAdESTestSignature {

    private DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> service;
    private DSSDocument documentToSign;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        service = new CBAdESService(getCompleteCertificateVerifier());
        documentToSign = new InMemoryDocument("Hello World!".getBytes(), "doc.txt");
        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);

        signatureParameters.setIncludeCertificateChainThumbprints(true);
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        KidCertificateSource signingCertificateSource = new KidCertificateSource();
        signingCertificateSource.addCertificate(getSigningCert());
        validator.setSigningCertificateSource(signingCertificateSource);
        return validator;
    }

    @Override
    protected void checkCOSESignStructure(COSESignStructure coseSignStructure) {
        super.checkCOSESignStructure(coseSignStructure);

        assertInstanceOf(COSESign.class, coseSignStructure);
        COSESign coseSign = (COSESign) coseSignStructure;
        assertEquals(1, coseSign.getSignatures().size());

        assertRequirementsValid(coseSign.getSignatures().get(0).getProtectedHeader());
    }

    private void assertRequirementsValid(COSEProtectedHeader protectedHeader) {
        CBORArray x5t = protectedHeader.getAsArray(COSEHeaderParameter.X5T.cbor());
        assertNull(x5t);

        CBORArray x5ts = protectedHeader.getAsArray(COSEHeaderParameter.X5TS.cbor());
        assertNotNull(x5ts);
        assertEquals(2, x5ts.getSize());

        for (CBORObject cborObject : x5ts.getValueAsList()) {
            assertTrue(cborObject.isArray());
            assertInstanceOf(CBORArray.class, cborObject);

            CBORArray x5tItem = (CBORArray) cborObject;

            Long algId = x5tItem.getAsLongOrString(COSEConstants.COSE_CERT_HASH_ALG);
            assertNotNull(algId);
            DigestAlgorithm digestAlgorithm = DigestAlgorithm.forCOSE(algId);
            assertEquals(getSignatureParameters().getSigningCertificateDigestMethod(), digestAlgorithm);

            byte[] hashValue = x5tItem.getAsBinaries(COSEConstants.COSE_CERT_HASH_VALUE);
            assertNotNull(hashValue);
        }

        CBORArray x5chain = protectedHeader.getAsArray(COSEHeaderParameter.X5CHAIN.cbor());
        assertNotNull(x5chain);
        assertEquals(2, x5chain.getSize());

        for (CBORObject cborObject : x5chain.getValueAsList()) {
            assertTrue(cborObject.isByteString());
            assertNotNull(cborObject.getValueAsBytes());
        }
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
                                                  DiagnosticData diagnosticData) {
        AdvancedSignature advancedSignature = advancedSignatures.get(0);
        assertEquals(2, advancedSignature.getCertificates().size());

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        List<RelatedCertificateWrapper> relatedCertificates = signatureWrapper.foundCertificates().getRelatedCertificates();
        assertEquals(2, relatedCertificates.size());

        RelatedCertificateWrapper signingCertificate = null;
        for (RelatedCertificateWrapper certificateWrapper : relatedCertificates) {
            assertTrue(Utils.isCollectionNotEmpty(certificateWrapper.getOrigins()));
            assertEquals(CertificateOrigin.KEY_INFO, certificateWrapper.getOrigins().get(0));
            if (signatureWrapper.getSigningCertificate().getId().equals(certificateWrapper.getId())) {
                signingCertificate = certificateWrapper;
                break;
            }
        }
        assertNotNull(signingCertificate);

        boolean signCertFound = false;
        boolean keyIdentifierFound = false;
        for (CertificateRefWrapper certificateRefWrapper : signingCertificate.getReferences()) {
            if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRefWrapper.getOrigin())) {
                signCertFound = true;
            } else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRefWrapper.getOrigin())) {
                keyIdentifierFound = true;
            }
        }
        assertTrue(signCertFound);
        assertTrue(keyIdentifierFound);

        assertEquals(2, signatureWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
        assertEquals(1, signatureWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());

        assertNotNull(signatureWrapper.getSigningCertificate());
        assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getCertificateChain()));
    }

    @Override
    protected void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {
        // do nothing
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
