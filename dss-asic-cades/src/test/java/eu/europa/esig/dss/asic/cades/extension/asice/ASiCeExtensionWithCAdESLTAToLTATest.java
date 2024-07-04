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
package eu.europa.esig.dss.asic.cades.extension.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.extension.AbstractASiCWithCAdESTestExtension;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidator;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

// see DSS-1805
class ASiCeExtensionWithCAdESLTAToLTATest extends AbstractASiCWithCAdESTestExtension {

    private static Date currentDate = new Date();

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        List<DSSDocument> documentToSigns = new ArrayList<>();
        documentToSigns.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT));
        documentToSigns.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeTypeEnum.TEXT));

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        ASiCWithCAdESService service = new ASiCWithCAdESService(getCertificateVerifier());
        service.setTspSource(getGoodTsa());

        ToBeSigned dataToSign = service.getDataToSign(documentToSigns, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentToSigns, signatureParameters, signatureValue);
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getExtensionParameters() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(currentDate);
        calendar.add(Calendar.MONTH, 6);
        currentDate = calendar.getTime();

        ASiCWithCAdESService service = new ASiCWithCAdESService(getCertificateVerifier());
        service.setTspSource(getGoodTsaByTime(currentDate));

        ASiCWithCAdESSignatureParameters extendParameters = new ASiCWithCAdESSignatureParameters();
        extendParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        extendParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        return extendParameters;
    }

    private CertificateVerifier getCertificateVerifier() {
        CertificateVerifier completeCertificateVerifier = super.getCompleteCertificateVerifier();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(currentDate);
        calendar.add(Calendar.MINUTE, -1);
        PKICRLSource pKICRLSource = pkiCRLSource();
        pKICRLSource.setThisUpdate(calendar.getTime());
        completeCertificateVerifier.setCrlSource(pKICRLSource);
        completeCertificateVerifier.setOcspSource(null);
        return completeCertificateVerifier;
    }

    @Override
    protected void checkOriginalLevel(DiagnosticData diagnosticData) {
        super.checkOriginalLevel(diagnosticData);

        assertEquals(1, diagnosticData.getSignatures().size());
        assertEquals(2, diagnosticData.getTimestampList().size());
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        super.checkFinalLevel(diagnosticData);

        assertEquals(1, diagnosticData.getSignatures().size());
        assertEquals(3, diagnosticData.getTimestampList().size());
    }

    //pdcm
    @Override
    protected void checkValidationContext(SignedDocumentValidator validator) {
        super.checkValidationContext(validator);

        ASiCContainerWithCAdESValidator asicValidator = (ASiCContainerWithCAdESValidator) validator;

        List<DSSDocument> signatures = asicValidator.getSignatureDocuments();
        assertTrue(Utils.isCollectionNotEmpty(signatures));

        byte[] signatureDigest = signatures.get(0).getDigestValue(DigestAlgorithm.SHA512);

        List<DSSDocument> archiveManifests = asicValidator.getArchiveManifestDocuments();
        assertTrue(Utils.isCollectionNotEmpty(archiveManifests));

        for (DSSDocument archiveManifest : archiveManifests) {
            ManifestFile archiveManifestFile = ASiCManifestParser.getManifestFile(archiveManifest);
            Digest archManifestSigDigest = getSignatureDigest(archiveManifestFile);
            assertArrayEquals(signatureDigest, archManifestSigDigest.getValue());
        }
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<String> sigRevocationIds = signature.foundRevocations().getRelatedRevocationData()
				.stream().map(RevocationWrapper::getId).collect(Collectors.toList());
        sigRevocationIds.addAll(signature.foundRevocations().getOrphanRevocationData()
				.stream().map(OrphanTokenWrapper::getId).collect(Collectors.toList()));

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        if (timestampList.size() == 3) {
            TimestampWrapper firstArchiveTst = timestampList.get(1);
            assertTrue(Utils.isCollectionNotEmpty(firstArchiveTst.foundRevocations().getRelatedRevocationData()));
            for (RelatedRevocationWrapper revocation : firstArchiveTst.foundRevocations().getRelatedRevocationData()) {
                assertFalse(sigRevocationIds.contains(revocation.getId()));
            }
        }
    }

    private Digest getSignatureDigest(ManifestFile archiveManifestFile) {
        Digest digest = null;
        for (ManifestEntry entry : archiveManifestFile.getEntries()) {
            if ("META-INF/signature001.p7s".equals(entry.getUri())) {
                digest = entry.getDigest();
                break;
            }
        }
        assertNotNull(digest);
        return digest;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER_WITH_CRL_AND_OCSP;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

    @Override
    protected ASiCContainerType getContainerType() {
        return ASiCContainerType.ASiC_E;
    }

}
