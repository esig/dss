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
package eu.europa.esig.dss.asic.cades.timestamp;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidator;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESManifestParser;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCWithCAdESTimestampServiceTest extends PKIFactoryAccess {

    private TSPSource tspSource;
    private ASiCWithCAdESTimestampService timestampService;

    @BeforeEach
    public void init() {
        tspSource = getGoodTsa();
        timestampService = new ASiCWithCAdESTimestampService(tspSource);
    }

    @Test
    public void timestampFromDocumentsWithASiCSOneFileTest() throws IOException {
        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        List<DSSDocument> documentsToSign = Arrays.asList(documentToSign);

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        timestampParameters.setZipCreationDate(new Date());
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        DSSDocument asicContainer = timestampService.timestamp(documentsToSign, timestampParameters);

        ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(asicContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        List<TimestampToken> timestamps = validator.getDetachedTimestamps();
        assertEquals(1, timestamps.size());

        List<DSSDocument> manifestDocuments = validator.getManifestDocuments();
        assertEquals(0, manifestDocuments.size());

        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = verify(reports);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        TimestampWrapper timestampWrapper = timestampList.get(0);

        List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
        assertEquals(1, timestampScopes.size()); // 1 file
    }

    @Test
    public void timestampFromDocumentsWithASiCSMultipleFilesTest() throws IOException {
        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT);
        List<DSSDocument> documentsToSign = Arrays.asList(documentToSign, documentToSign2);

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        timestampParameters.setZipCreationDate(new Date());
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        DSSDocument asicContainer = timestampService.timestamp(documentsToSign, timestampParameters);

        ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(asicContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        List<TimestampToken> timestamps = validator.getDetachedTimestamps();
        assertEquals(1, timestamps.size());

        List<DSSDocument> manifestDocuments = validator.getManifestDocuments();
        assertEquals(0, manifestDocuments.size());

        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = verify(reports);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        TimestampWrapper timestampWrapper = timestampList.get(0);

        List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
        assertEquals(3, timestampScopes.size()); // 2 docs + package.zip
    }

    @Test
    public void timestampFromDocumentsWithASiCEOneFileTest() throws IOException {
        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        List<DSSDocument> documentsToSign = Arrays.asList(documentToSign);

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        timestampParameters.setZipCreationDate(new Date());
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        DSSDocument asicContainer = timestampService.timestamp(documentsToSign, timestampParameters);

        ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(asicContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        List<TimestampToken> timestamps = validator.getDetachedTimestamps();
        assertEquals(1, timestamps.size());

        List<DSSDocument> manifestDocuments = validator.getManifestDocuments();
        assertEquals(1, manifestDocuments.size());

        ManifestFile coveredManifest = ASiCWithCAdESManifestParser.getManifestFile(manifestDocuments.get(0));
        assertNotNull(coveredManifest);

        List<ManifestEntry> entries = coveredManifest.getEntries();
        assertEquals(1, entries.size());

        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = verify(reports);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        TimestampWrapper timestampWrapper = timestampList.get(0);

        List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
        assertEquals(2, timestampScopes.size()); // doc + manifest
    }

    @Test
    public void timestampFromDocumentsWithASiCEMultilpeFilesTest() throws IOException {
        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT);
        List<DSSDocument> documentsToSign = Arrays.asList(documentToSign, documentToSign2);

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        timestampParameters.setZipCreationDate(new Date());
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        DSSDocument asicContainer = timestampService.timestamp(documentsToSign, timestampParameters);
        // asicContainer.save("target/timestamped.scs");

        ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(asicContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        List<TimestampToken> timestamps = validator.getDetachedTimestamps();
        assertEquals(1, timestamps.size());

        List<DSSDocument> manifestDocuments = validator.getManifestDocuments();
        assertEquals(1, manifestDocuments.size());

        ManifestFile coveredManifest = ASiCWithCAdESManifestParser.getManifestFile(manifestDocuments.get(0));
        assertNotNull(coveredManifest);

        List<ManifestEntry> entries = coveredManifest.getEntries();
        assertEquals(2, entries.size());

        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = verify(reports);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        TimestampWrapper timestampWrapper = timestampList.get(0);

        List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
        assertEquals(3, timestampScopes.size()); // 2 docs + manifest
    }

    @Test
    public void timestampFromASiCContentWithASiCSTest() throws IOException {
        ASiCContent asicContent = new ASiCContent();

        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT);
        asicContent.setSignedDocuments(Arrays.asList(documentToSign, documentToSign2));

        asicContent.setUnsupportedDocuments(Collections.singletonList(
                new InMemoryDocument("unsupported".getBytes(), "other-docs/doc.txt", MimeType.TEXT)));

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        timestampParameters.setZipCreationDate(new Date());
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        asicContent = timestampService.timestamp(asicContent, timestampParameters);
        DSSDocument asicContainer = ZipUtils.getInstance().createZipArchive(asicContent, new Date());

        ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(asicContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        List<TimestampToken> timestamps = validator.getDetachedTimestamps();
        assertEquals(1, timestamps.size());

        List<DSSDocument> manifestDocuments = validator.getManifestDocuments();
        assertEquals(0, manifestDocuments.size());

        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = verify(reports);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        TimestampWrapper timestampWrapper = timestampList.get(0);

        List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
        assertEquals(3, timestampScopes.size()); // 2 docs + package.zip

        ASiCContent extractedContainer = new ASiCWithCAdESContainerExtractor(asicContainer).extract();
        assertNotNull(extractedContainer);

        assertEquals(0, extractedContainer.getSignatureDocuments().size());
        assertEquals(1, extractedContainer.getTimestampDocuments().size());
        assertEquals(2, extractedContainer.getSignedDocuments().size()); // package.zip + unsupported file
        assertEquals(0, extractedContainer.getManifestDocuments().size());
    }

    @Test
    public void timestampFromASiCContentWithASiCETest() throws IOException {
        ASiCContent asicContent = new ASiCContent();

        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT);
        asicContent.setSignedDocuments(Arrays.asList(documentToSign, documentToSign2));

        asicContent.setUnsupportedDocuments(Collections.singletonList(
                new InMemoryDocument("unsupported".getBytes(), "other-docs/doc.txt", MimeType.TEXT)));

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        timestampParameters.setZipCreationDate(new Date());
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        asicContent = timestampService.timestamp(asicContent, timestampParameters);
        DSSDocument asicContainer = ZipUtils.getInstance().createZipArchive(asicContent, new Date());

        ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(asicContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        List<TimestampToken> timestamps = validator.getDetachedTimestamps();
        assertEquals(1, timestamps.size());

        List<DSSDocument> manifestDocuments = validator.getManifestDocuments();
        assertEquals(1, manifestDocuments.size());

        ManifestFile coveredManifest = ASiCWithCAdESManifestParser.getManifestFile(manifestDocuments.get(0));
        assertNotNull(coveredManifest);

        List<ManifestEntry> entries = coveredManifest.getEntries();
        assertEquals(2, entries.size());

        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = verify(reports);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        TimestampWrapper timestampWrapper = timestampList.get(0);

        List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
        assertEquals(3, timestampScopes.size()); // 2 docs + manifest

        ASiCContent extractedContainer = new ASiCWithCAdESContainerExtractor(asicContainer).extract();
        assertNotNull(extractedContainer);

        assertEquals(0, extractedContainer.getSignatureDocuments().size());
        assertEquals(1, extractedContainer.getTimestampDocuments().size());
        assertEquals(3, extractedContainer.getSignedDocuments().size()); // 2 docs + unsupported file
        assertEquals(1, extractedContainer.getManifestDocuments().size());
    }

    private DiagnosticData verify(Reports reports) {
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());

        for (TimestampWrapper timestampWrapper : timestampList) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureValid());
        }

        return diagnosticData;
    }

    @Override
    protected String getSigningAlias() {
        return null;
    }

}
