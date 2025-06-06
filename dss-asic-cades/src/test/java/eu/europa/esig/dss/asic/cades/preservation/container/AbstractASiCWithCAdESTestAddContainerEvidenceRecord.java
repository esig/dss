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
package eu.europa.esig.dss.asic.cades.preservation.container;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.validation.evidencerecord.AbstractASiCWithCAdESWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.asic.common.ASiCContainerEvidenceRecordParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractASiCWithCAdESTestAddContainerEvidenceRecord extends AbstractASiCWithCAdESWithEvidenceRecordTestValidation {

    protected abstract List<DSSDocument> getDocumentsToPreserve();

    protected abstract DSSDocument getEvidenceRecordDocument();

    protected ASiCContainerEvidenceRecordParameters getASiCContainerEvidenceRecordParameters() {
        ASiCContainerEvidenceRecordParameters parameters = new ASiCContainerEvidenceRecordParameters();
        parameters.setContainerType(getASiCContainerType());
        parameters.setAsicEvidenceRecordManifest(getASiCEvidenceRecordManifest());
        return parameters;
    }

    protected abstract ASiCContainerType getASiCContainerType();

    protected DSSDocument getASiCEvidenceRecordManifest() {
        return null;
    }

    protected ASiCWithCAdESService getService() {
        return new ASiCWithCAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument getSignedDocument() {
        ASiCWithCAdESService service = getService();
        return service.addContainerEvidenceRecord(getDocumentsToPreserve(), getEvidenceRecordDocument(), getASiCContainerEvidenceRecordParameters());
    }

    @Override
    public void validate() {
        // skip
    }

    @Test
    public void addERAndValidate() {
        super.validate();
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        // skip
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        // skip (out of scope)
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);
        checkEvidenceRecordFilename(diagnosticData);
    }

    protected void checkEvidenceRecordFilename(DiagnosticData diagnosticData) {
        for (EvidenceRecordWrapper evidenceRecordWrapper : diagnosticData.getEvidenceRecords()) {
            ASiCContainerType asicContainerType = getASiCContainerType();
            if (ASiCContainerType.ASiC_S == asicContainerType) {
                if (EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD == evidenceRecordWrapper.getEvidenceRecordType()) {
                    assertEquals("META-INF/evidencerecord.xml", evidenceRecordWrapper.getFilename());
                } else if (EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD == evidenceRecordWrapper.getEvidenceRecordType()) {
                    assertEquals("META-INF/evidencerecord.ers", evidenceRecordWrapper.getFilename());
                } else {
                    fail(String.format("The evidence record type '%s' is not supported!", evidenceRecordWrapper.getEvidenceRecordType()));
                }

            } else if (ASiCContainerType.ASiC_E == asicContainerType){
                assertTrue(evidenceRecordWrapper.getFilename().startsWith("META-INF/"));
                assertTrue(evidenceRecordWrapper.getFilename().contains("evidencerecord"));
                if (EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD == evidenceRecordWrapper.getEvidenceRecordType()) {
                    assertTrue(evidenceRecordWrapper.getFilename().endsWith(".xml"));
                } else if (EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD == evidenceRecordWrapper.getEvidenceRecordType()) {
                    assertTrue(evidenceRecordWrapper.getFilename().endsWith(".ers"));
                } else {
                    fail(String.format("The evidence record type '%s' is not supported!", evidenceRecordWrapper.getEvidenceRecordType()));
                }

            } else {
                fail(String.format("The ASiC container type '%s' is not supported!", asicContainerType));
            }
        }
    }

    @Override
    protected void checkEvidenceRecordType(EvidenceRecordWrapper evidenceRecord) {
        super.checkEvidenceRecordType(evidenceRecord);

        assertEquals(getEvidenceRecordType(), evidenceRecord.getEvidenceRecordType());
    }

    protected abstract EvidenceRecordTypeEnum getEvidenceRecordType();

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        super.checkContainerInfo(diagnosticData);

        assertEquals(getASiCContainerType(), diagnosticData.getContainerType());
        if (ASiCContainerType.ASiC_E == getASiCContainerType()) {
            List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
            assertTrue(Utils.isCollectionNotEmpty(manifestFiles));
            for (XmlManifestFile xmlManifestFile : manifestFiles) {
                if (xmlManifestFile.getSignatureFilename().contains("evidencerecord")) {
                    DSSDocument asicEvidenceRecordManifest = getASiCEvidenceRecordManifest();
                    if (asicEvidenceRecordManifest != null && asicEvidenceRecordManifest.getName() != null) {
                        assertEquals(asicEvidenceRecordManifest.getName(), xmlManifestFile.getFilename());
                    } else {
                        assertTrue(xmlManifestFile.getFilename().startsWith("META-INF/ASiCEvidenceRecordManifest"));
                        assertTrue(xmlManifestFile.getFilename().endsWith(".xml"));
                    }
                    assertEquals(getNumberOfExpectedEvidenceScopes(), xmlManifestFile.getEntries().size());
                }
            }
        }
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        // skip
    }

}
