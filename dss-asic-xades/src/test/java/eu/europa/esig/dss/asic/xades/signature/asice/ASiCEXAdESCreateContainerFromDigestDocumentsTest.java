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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESASiCContentBuilder;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.DefaultASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Date;

class ASiCEXAdESCreateContainerFromDigestDocumentsTest extends AbstractASiCEXAdESTestSignature {

    private XAdESService service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private DSSDocument originalDocument;

    @BeforeEach
    void init() throws Exception {
        originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        InMemoryDocument rootDocument = new InMemoryDocument(("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>" +
                "<asic:XAdESSignatures xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\"></asic:XAdESSignatures>").getBytes());
        signatureParameters.setRootDocument(rootDocument);

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        DigestDocument digestDocument = new DigestDocument(originalDocument.getDigest(signatureParameters.getDigestAlgorithm()), originalDocument.getName());

        ToBeSigned dataToSign = service.getDataToSign(digestDocument, signatureParameters);
        byte[] dtbsr = DSSUtils.digest(signatureParameters.getDigestAlgorithm(), dataToSign.getBytes());

        SignatureValue signatureValue = getToken().signDigest(new Digest(signatureParameters.getDigestAlgorithm(), dtbsr),
                signatureParameters.getSignatureAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(digestDocument, signatureParameters, signatureValue);

        ASiCContent asicContent = new ASiCWithXAdESASiCContentBuilder().build(
                Collections.singletonList(originalDocument), signatureParameters.aSiC().getContainerType());

        DefaultASiCWithXAdESFilenameFactory asicWithXAdESFilenameFactory = new DefaultASiCWithXAdESFilenameFactory();

        String signatureFilename = asicWithXAdESFilenameFactory.getSignatureFilename(asicContent);
        signedDocument.setName(signatureFilename);

        String manifestFilename = asicWithXAdESFilenameFactory.getManifestFilename(asicContent);

        DSSDocument manifestDocument = new ASiCEWithXAdESManifestBuilder().setManifestFilename(manifestFilename)
                .setDocuments(Collections.singletonList(digestDocument)).build();

        asicContent.setManifestDocuments(Collections.singletonList(manifestDocument));
        asicContent.setSignatureDocuments(Collections.singletonList(signedDocument));

        ASiCUtils.ensureMimeTypeAndZipComment(asicContent, signatureParameters.aSiC());
        MimeType mimeType = ASiCUtils.getMimeType(asicContent.getMimeTypeDocument());

        DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContent);
        zipArchive.setName("asic." + mimeType.getExtension());
        zipArchive.setMimeType(mimeType);
        return zipArchive;
    }

    @Override
    protected ASiCWithXAdESService getService() {
        return new ASiCWithXAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return originalDocument;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
