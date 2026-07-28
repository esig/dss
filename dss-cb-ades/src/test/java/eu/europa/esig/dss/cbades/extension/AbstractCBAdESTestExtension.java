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
package eu.europa.esig.dss.cbades.extension;

import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.COSESign;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cbades.signature.CBAdESTimestampParameters;
import eu.europa.esig.dss.cbades.validation.CBAdESCertificateSource;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.extension.AbstractTestExtension;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractCBAdESTestExtension
        extends AbstractTestExtension<CBAdESSignatureParameters, CBAdESTimestampParameters> {

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        return getGoodTsa();
    }

    @Override
    protected TSPSource getUsedTSPSourceAtExtensionTime() {
        return getAlternateGoodTsa();
    }

    @Override
    protected void onDocumentExtended(DSSDocument extendedDocument) {
        super.onDocumentExtended(extendedDocument);

        assertTrue(COSEParser.isSupported(extendedDocument));

        COSEParser coseParser = COSEParser.fromDocument(extendedDocument);
        COSESignStructure coseSignStructure = coseParser.parse();
        checkCOSESignStructure(coseSignStructure);
    }

    protected void checkCOSESignStructure(COSESignStructure coseSignStructure) {
        assertNotNull(coseSignStructure);

        assertNotNull(coseSignStructure.getContext());

        assertEquals(COSEStructureType.COSE_SIGN == getSignatureParameters().getCoseStructureType(),
                coseSignStructure instanceof COSESign);
        assertEquals(COSEStructureType.COSE_SIGN1 == getSignatureParameters().getCoseStructureType(),
                coseSignStructure instanceof COSESign1);

        boolean isTagged = Utils.isTrue(getSignatureParameters().isTagged()) || getSignatureParameters().isTagged() == null;
        assertEquals(isTagged, coseSignStructure.isTagged());

        assertNotNull(coseSignStructure.getPayload());
        assertEquals(SignaturePackaging.DETACHED == getSignatureParameters().getSignaturePackaging(), coseSignStructure.getPayload().isNull());
    }

    @Override
    protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertNotNull(signatureWrapper.getSignatureValue());
        }
    }

    @Override
    protected void checkReportsSignatureIdentifier(Reports reports) {
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        for (SignatureValidationReportType signatureValidationReport : etsiValidationReport
                .getSignatureValidationReport()) {
            SignatureWrapper signature = diagnosticData
                    .getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());

            SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
            assertNotNull(signatureIdentifier);

            assertNotNull(signatureIdentifier.getSignatureValue());
            assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertTrue(signatureWrapper.isSigningCertificateIdentified());
            assertTrue(signatureWrapper.isSigningCertificateReferencePresent());

            CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
            assertNotNull(signingCertificateReference);
            assertTrue(signingCertificateReference.isDigestValuePresent());
            assertTrue(signingCertificateReference.isDigestValueMatch());
            if (signingCertificateReference.isIssuerSerialPresent()) {
                assertTrue(signingCertificateReference.isIssuerSerialMatch());
            }

            CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
            assertNotNull(signingCertificate);
            String signingCertificateId = signingCertificate.getId();
            String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
            String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
            assertEquals(signingCertificate.getCertificateDN(), certificateDN);
            assertEquals(signingCertificate.getSerialNumber(), certificateSerialNumber);

            assertTrue(Utils.isCollectionEmpty(signatureWrapper.foundCertificates()
                    .getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

            FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
            List<RelatedCertificateWrapper> signingCertificates = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
            assertTrue(Utils.isCollectionNotEmpty(signingCertificates));

            List<CertificateRefWrapper> signingCertificateRefs = null;
            for (RelatedCertificateWrapper certificateWrapper : signingCertificates) {
                if (signatureWrapper.getSigningCertificate().getId().equals(certificateWrapper.getId())) {
                    signingCertificateRefs = certificateWrapper.getReferences();
                    break;
                }
            }
            assertNotNull(signingCertificateRefs);

            List<RelatedCertificateWrapper> kidCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER);
            List<RelatedCertificateWrapper> x5uCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.X509_URL);

            int signCertRefs = 1 + (Utils.isCollectionNotEmpty(kidCerts) ? 1 : 0) + (Utils.isCollectionNotEmpty(x5uCerts) ? 1 : 0);
            assertEquals(signCertRefs, signingCertificateRefs.size());

            if (getSignatureParameters().isIncludeKeyIdentifier()) {
                assertEquals(1, kidCerts.size());
            } else if (Utils.isStringNotEmpty(getSignatureParameters().getX509Url())) {
                assertTrue(Utils.isCollectionNotEmpty(x5uCerts));
            } else {
                assertEquals(0, kidCerts.size());
                assertEquals(0, x5uCerts.size());
            }

            for (CertificateRefWrapper certificateRef : signingCertificateRefs) {
                if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getDigestAlgoAndValue());
                    assertNotNull(certificateRef.getDigestMethod());
                    assertTrue(certificateRef.isDigestValuePresent());
                    assertTrue(certificateRef.isDigestValueMatch());
                    assertNull(certificateRef.getIssuerSerial());

                } else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getCertificateId());
                    assertNotNull(certificateRef.getIssuerSerial());
                    assertTrue(certificateRef.isIssuerSerialPresent());
                    assertTrue(certificateRef.isIssuerSerialMatch());
                    assertNull(certificateRef.getDigestAlgoAndValue());
                }
            }
        }
    }

    @Override
    protected FileDocument getOriginalDocument() {
        File originalDoc = new File("target/original-" + UUID.randomUUID() + ".xml");
        try (FileOutputStream fos = new FileOutputStream(originalDoc);
             InputStream is = new InMemoryDocument("Hello world!".getBytes(), "HelloWorld").openStream()) {
            Utils.copy(is, fos);
        } catch (IOException e) {
            throw new DSSException("Unable to create the original document", e);
        }
        return new FileDocument(originalDoc);
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        // Sign
        CBAdESSignatureParameters signatureParameters = getSignatureParameters();
        CBAdESService service = getSignatureServiceToSign();

        ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
                getPrivateKeyEntry());
        return service.signDocument(doc, signatureParameters, signatureValue);
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        // Sign
        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
        return signatureParameters;
    }

    @Override
    protected CBAdESService getSignatureServiceToSign() {
        CBAdESService service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getUsedTSPSourceAtSignatureTime());
        return service;
    }

    @Override
    protected CBAdESService getSignatureServiceToExtend() {
        CBAdESService service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
        return service;
    }

    @Override
    protected CBAdESSignatureParameters getExtensionParameters() {
        CBAdESSignatureParameters extensionParameters = new CBAdESSignatureParameters();
        extensionParameters.setSignatureLevel(getFinalSignatureLevel());
        extensionParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        return extensionParameters;
    }

    @Override
    protected void verifyCertificateSourceData(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
        super.verifyCertificateSourceData(certificateSource, foundCertificates);

        if (certificateSource instanceof CBAdESCertificateSource) {
            CBAdESCertificateSource cbadesCertificateSource = (CBAdESCertificateSource) certificateSource;
            assertEquals(cbadesCertificateSource.getKeyIdentifierCertificates().size(),
                    foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size() +
                            foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
            assertEquals(cbadesCertificateSource.getKeyIdentifierCertificateRefs().size(),
                    foundCertificates.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size() +
                            foundCertificates.getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
        }
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
