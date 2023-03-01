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
package eu.europa.esig.dss.asic.cades.timestamp.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.signature.asice.AbstractASiCEWithCAdESMultipleDocumentsTestSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCETimestampLevelLTSignatureTest extends AbstractASiCEWithCAdESMultipleDocumentsTestSignature {

    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentsToSign;

    @BeforeEach
    public void init() throws Exception {
        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());

        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeTypeEnum.TEXT);
        documentsToSign = Arrays.asList(documentToSign, documentToSign2);

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        return service.timestamp(signedDocument, timestampParameters);
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        assertEquals(1, signatures.size());
    }

    @Override
    protected void checkDetachedTimestamps(List<TimestampToken> detachedTimestamps) {
        super.checkDetachedTimestamps(detachedTimestamps);

        assertEquals(1, detachedTimestamps.size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        assertEquals(1, diagnosticData.getSignatures().size());
        assertEquals(2, diagnosticData.getTimestampList().size());

        SignatureWrapper signatureWrapper = diagnosticData.getSignatures().get(0);
        List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
        assertEquals(3, signatureScopes.size());

        Set<String> signedDataIds = new HashSet<>();
        String signedManifestId = null;
        for (XmlSignatureScope signatureScope : signatureScopes) {
            for (DSSDocument doc : documentsToSign) {
                if (doc.getName().equals(signatureScope.getName())) {
                    signedDataIds.add(signatureScope.getSignerData().getId());
                }
            }
            if ("META-INF/ASiCManifest001.xml".equals(signatureScope.getName())) {
                signedManifestId = signatureScope.getSignerData().getId();
            }
        }
        assertEquals(2, signedDataIds.size());
        assertNotNull(signedManifestId);

        boolean sigTstFound = false;
        boolean detachedTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertEquals(3, timestampWrapper.getTimestampedSignedData().size()); // signedDocs + Manifest
                assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
                assertEquals(0, timestampWrapper.getTimestampedTimestamps().size());
                sigTstFound = true;

            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertEquals(4, timestampWrapper.getTimestampedSignedData().size()); // signedDocs + ArchiveManifest + signatureManifest
                assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
                assertEquals(1, timestampWrapper.getTimestampedTimestamps().size()); // signature time-stamp

                Set<String> timestampedDataIds = new HashSet<>();
                String timestampedManifestId = null;
                for (SignerDataWrapper signerDataWrapper : timestampWrapper.getTimestampedSignedData()) {
                    for (DSSDocument doc : documentsToSign) {
                        if (doc.getName().equals(signerDataWrapper.getReferencedName())) {
                            timestampedDataIds.add(signerDataWrapper.getId());
                        }
                    }
                    if ("META-INF/ASiCArchiveManifest.xml".equals(signerDataWrapper.getReferencedName())) {
                        timestampedManifestId = signerDataWrapper.getId();
                    }
                }
                assertEquals(2, timestampedDataIds.size());
                assertNotNull(timestampedManifestId);

                assertEquals(signedDataIds, timestampedDataIds);
                assertNotEquals(signedManifestId, timestampedManifestId);

                detachedTstFound = true;
            }
        }
        assertTrue(sigTstFound);
        assertTrue(detachedTstFound);
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentsToSign;
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
