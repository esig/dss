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

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBTest extends AbstractCBAdESTestSignature {

    private DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> service;
    private DSSDocument documentToSign;

    private Date signingDate;

    @BeforeEach
    void init() throws Exception {
        service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = new InMemoryDocument("Hello world!".getBytes());
        signingDate = new Date();
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN);
        signatureParameters.setTagged(true);
        signatureParameters.setIncludeKeyIdentifier(true);
        SignerLocation signerLocation = new SignerLocation();
        signerLocation.setLocality("Kehlen");
        signerLocation.setPostOfficeBoxNumber("2C");
        signerLocation.setPostalCode("L-8287");
        signatureParameters.bLevel().setSignerLocation(signerLocation);
        signatureParameters.bLevel().setCommitmentTypeIndications(Collections.singletonList(CommitmentTypeEnum.ProofOfCreation));
        return signatureParameters;
    }

    @Override
    protected void checkCommitmentTypeIndications(DiagnosticData diagnosticData) {
        super.checkCommitmentTypeIndications(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlCommitmentTypeIndication> commitmentTypeIndications = signature.getCommitmentTypeIndications();
        assertEquals(1, commitmentTypeIndications.size());
        XmlCommitmentTypeIndication commitmentTypeIndication = commitmentTypeIndications.get(0);
        assertEquals(CommitmentTypeEnum.ProofOfCreation.getUri(), commitmentTypeIndication.getIdentifier());
        assertEquals(CommitmentTypeEnum.ProofOfCreation.getDescription(), commitmentTypeIndication.getDescription());
        assertEquals(CommitmentTypeEnum.ProofOfCreation.getDocumentationReferences().length,
                commitmentTypeIndication.getDocumentationReferences().size());
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        super.checkSigningCertificateValue(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        List<RelatedCertificateWrapper> signCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        assertEquals(1, signCerts.size());


        RelatedCertificateWrapper signingCertificate = null;
        for (RelatedCertificateWrapper certificateWrapper : signCerts) {
            assertTrue(Utils.isCollectionNotEmpty(certificateWrapper.getOrigins()));
            assertEquals(CertificateOrigin.KEY_INFO, certificateWrapper.getOrigins().get(0));
            if (signature.getSigningCertificate().getId().equals(certificateWrapper.getId())) {
                signingCertificate = certificateWrapper;
                break;
            }
        }
        assertNotNull(signingCertificate);

        assertEquals(2, signingCertificate.getReferences().size());

        boolean signCertRefFound = false;
        boolean kidCertRefFound = false;
        for (CertificateRefWrapper certificateRefWrapper : signingCertificate.getReferences()) {
            if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRefWrapper.getOrigin())) {
                signCertRefFound = true;
            } else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRefWrapper.getOrigin())) {
                kidCertRefFound = true;
            }
        }
        assertTrue(signCertRefFound);
        assertTrue(kidCertRefFound);
    }

    @Override
    protected void checkDTBSR(DiagnosticData diagnosticData) {
        super.checkDTBSR(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        XmlDigestAlgoAndValue dtbsr = signature.getDataToBeSignedRepresentation();

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, getSignatureParameters());
        assertArrayEquals(DSSUtils.digest(dtbsr.getDigestMethod(), dataToSign.getBytes()), dtbsr.getDigestValue());
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
