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
import eu.europa.esig.dss.asic.cades.signature.asice.AbstractASiCECAdESTestSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ASiCETimestampSignedContainerTest extends AbstractASiCECAdESTestSignature {

    private DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());

        documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
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
    protected void checkValidationContext(SignedDocumentValidator validator) {
        super.checkValidationContext(validator);

        assertEquals(1, validator.getSignatures().size());
    }

    @Override
    protected void checkDetachedTimestamps(List<TimestampToken> detachedTimestamps) {
        super.checkDetachedTimestamps(detachedTimestamps);

        assertEquals(1, detachedTimestamps.size());
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        assertEquals(1, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getTimestampList().size());

        SignatureWrapper signatureWrapper = diagnosticData.getSignatures().get(0);
        List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
        assertEquals(2, signatureScopes.size());

        String signedDataId = null;
        String signedManifestId = null;
        for (XmlSignatureScope signatureScope : signatureScopes) {
            if (documentToSign.getName().equals(signatureScope.getName())) {
                signedDataId = signatureScope.getSignerData().getId();
            } else if ("META-INF/ASiCManifest001.xml".equals(signatureScope.getName())) {
                signedManifestId = signatureScope.getSignerData().getId();
            }
        }
        assertNotNull(signedDataId);
        assertNotNull(signedManifestId);

        TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
        assertEquals(2, timestampWrapper.getTimestampedSignedData().size()); // signedDoc + Manifest
        assertEquals(0, timestampWrapper.getTimestampedSignatures().size());

        String timestampedDataId = null;
        String timestampedManifestId = null;
        for (SignerDataWrapper signerDataWrapper : timestampWrapper.getTimestampedSignedData()) {
            if (documentToSign.getName().equals(signerDataWrapper.getReferencedName())) {
                timestampedDataId = signerDataWrapper.getId();
            } else if ("META-INF/ASiCManifest002.xml".equals(signerDataWrapper.getReferencedName())) {
                timestampedManifestId = signerDataWrapper.getId();
            }
        }
        assertNotNull(timestampedDataId);
        assertNotNull(timestampedManifestId);

        assertEquals(signedDataId, timestampedDataId);
        assertNotEquals(signedManifestId, timestampedManifestId);
    }

    @Override
    protected DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
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
