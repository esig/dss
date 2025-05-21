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
package eu.europa.esig.dss.validation.process.vpfswatsp.evidencerecord.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AbstractSignedAndTimestampedFilesCoveredCheck;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class verifies whether all signed and/or time-asserted file objects are subsequently covered by the evidence record
 *
 */
public class EvidenceRecordSignedAndTimestampedFilesCoveredCheck extends AbstractSignedAndTimestampedFilesCoveredCheck<XmlValidationProcessEvidenceRecord> {

    /** Evidence record to be validated */
    private final EvidenceRecordWrapper evidenceRecordWrapper;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationProcessEvidenceRecord}
     * @param containerInfo {@link XmlContainerInfo}
     * @param evidenceRecordWrapper {@link EvidenceRecordWrapper}
     * @param constraint {@link LevelRule}
     */
    public EvidenceRecordSignedAndTimestampedFilesCoveredCheck(I18nProvider i18nProvider, XmlValidationProcessEvidenceRecord result,
            XmlContainerInfo containerInfo, EvidenceRecordWrapper evidenceRecordWrapper, LevelRule constraint) {
        super(i18nProvider, result, containerInfo, evidenceRecordWrapper.getFilename(), constraint);

        this.evidenceRecordWrapper = evidenceRecordWrapper;
    }

    @Override
    protected boolean process() {
        if (!super.process()) {
            return false;
        }

        List<String> coveredDocumentEntries = getCoveredDocumentEntries();
        if (Utils.isCollectionNotEmpty(coveredDocumentEntries)) {
            for (String coveredDocumentName : coveredDocumentEntries) {
                XmlManifestFile manifestFile = getCorrespondingManifestFile(coveredDocumentName);
                if (manifestFile != null) {
                    if (!checkManifestFilesCoveredRecursively(coveredDocumentEntries, manifestFile)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private List<String> getCoveredDocumentEntries() {
        List<String> result = evidenceRecordWrapper.getDigestMatchers().stream()
                .map(XmlDigestMatcher::getDocumentName).filter(Objects::nonNull).collect(Collectors.toList());
        if (evidenceRecordWrapper.isEmbedded() && evidenceRecordWrapper.getParent() != null
                && evidenceRecordWrapper.getParent().getFilename() != null) {
            result.add(evidenceRecordWrapper.getParent().getFilename());
        }
        return result;
    }

}
