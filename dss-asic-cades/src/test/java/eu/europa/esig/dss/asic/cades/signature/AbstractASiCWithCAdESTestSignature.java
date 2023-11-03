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
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCTestSignature;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.bouncycastle.cms.CMSSignedData;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCWithCAdESTestSignature
        extends AbstractASiCTestSignature<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> {

    @Override
    protected ASiCWithCAdESContainerExtractor getContainerExtractor(DSSDocument document) {
        return new ASiCWithCAdESContainerExtractor(document);
    }

    @Override
    protected List<DSSDocument> getOriginalDocuments() {
        return Collections.singletonList(getDocumentToSign());
    }

    @Override
    protected boolean isBaselineT() {
        SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
        return SignatureLevel.CAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.CAdES_BASELINE_LT.equals(signatureLevel)
                || SignatureLevel.CAdES_BASELINE_T.equals(signatureLevel);
    }

    @Override
    protected boolean isBaselineLTA() {
        return SignatureLevel.CAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        ASiCWithCAdESContainerExtractor containerExtractor = new ASiCWithCAdESContainerExtractor(new InMemoryDocument(byteArray));
        ASiCContent asicContent = containerExtractor.extract();
        checkExtractedContent(asicContent);

        List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
        assertTrue(Utils.isCollectionNotEmpty(signatureDocuments));
        for (DSSDocument signatureDocument : signatureDocuments) {
            checkSignaturePackaging(signatureDocument);
        }
        checkManifests(asicContent.getAllManifestDocuments());
    }

    protected void checkExtractedContent(ASiCContent asicContent) {
        assertNotNull(asicContent);
        assertTrue(Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()));
        assertNotNull(asicContent.getMimeTypeDocument());
        if (getSignatureParameters().aSiC().isZipComment()) {
            assertTrue(Utils.isStringNotBlank(asicContent.getZipComment()));
        }
        if (SignatureLevel.CAdES_BASELINE_LTA == getSignatureParameters().getSignatureLevel() &&
                ASiCContainerType.ASiC_E == getSignatureParameters().aSiC().getContainerType()) {
            assertTrue(Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()));
            assertTrue(Utils.isCollectionNotEmpty(asicContent.getArchiveManifestDocuments()));
        } else {
            assertFalse(Utils.isCollectionNotEmpty(asicContent.getArchiveManifestDocuments()));
        }
    }

    protected void checkManifests(List<DSSDocument> manifestDocuments) {
        for (DSSDocument document : manifestDocuments) {
            ManifestFile manifestFile = ASiCManifestParser.getManifestFile(document);
            assertNotNull(manifestFile);

            assertNotNull(manifestFile.getFilename());
            assertNotNull(manifestFile.getSignatureFilename());
            assertTrue(Utils.isCollectionNotEmpty(manifestFile.getEntries()));
            for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                assertNotNull(manifestEntry.getFileName());
                assertNotNull(manifestEntry.getDigest());
                assertNotNull(manifestEntry.getMimeType());
                assertTrue(Utils.isStringNotEmpty(manifestEntry.getMimeType().getMimeTypeString()));
            }
        }
    }

    protected void checkSignaturePackaging(DSSDocument signatureDocument) {
        CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(signatureDocument);
        assertTrue(cmsSignedData.isDetachedSignature());
        assertNull(cmsSignedData.getSignedContent());
    }

    protected abstract DSSDocument getSignedData(ASiCContent extractResult);

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertEquals(getExpectedASiCContainerType(), diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
    }

    protected abstract ASiCContainerType getExpectedASiCContainerType();

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

        if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
            for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
                SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());

                SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
                assertNotNull(signatureIdentifier);

                assertNotNull(signatureIdentifier.getSignatureValue());
                assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
            }
        }
    }

    @Override
    protected void checkMimeType(DiagnosticData diagnosticData) {
        super.checkMimeType(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (!signatureWrapper.isCounterSignature() && Utils.isStringEmpty(signatureWrapper.getContentHints())) {
                assertNotNull(signatureWrapper.getMimeType());
            } else {
                assertNull(signatureWrapper.getMimeType());
            }
        }
    }

}
