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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.ArrayList;
import java.util.List;

/**
 * This class checks whether all files signed by the covered signatures or timestamped by covered timestamps
 * are covered by the current timestamp as well
 * @param <T> {@code XmlConstraintsConclusion}
 *
 */
public abstract class AbstractSignedAndTimestampedFilesCoveredCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** ASiC Container info */
    private final XmlContainerInfo containerInfo;

    /** Filename of the timestamp file to be verified */
    private final String timestampFilename;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param containerInfo {@link XmlContainerInfo}
     * @param timestampFilename {@link String}
     * @param constraint {@link LevelConstraint}
     */
    protected AbstractSignedAndTimestampedFilesCoveredCheck(I18nProvider i18nProvider, T result, XmlContainerInfo containerInfo,
                                                            String timestampFilename, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.containerInfo = containerInfo;
        this.timestampFilename = timestampFilename;
    }

    @Override
    protected boolean process() {
        XmlManifestFile manifestFile = getCorrespondingManifestFile(timestampFilename);
        if (manifestFile != null) {
            return checkManifestFilesCovered(manifestFile) && isAnyRootLevelDocumentCovered(manifestFile);
        }
        // no manifest -> no check is required (ASiC-S case)
        return true;
    }

    private boolean checkManifestFilesCovered(XmlManifestFile timestampManifest) {
        return checkManifestFilesCoveredRecursively(timestampManifest, timestampManifest);
    }

    private boolean checkManifestFilesCoveredRecursively(XmlManifestFile timestampManifest, XmlManifestFile currentManifestFile) {
        if (currentManifestFile != null) {
            for (String manifestEntry : currentManifestFile.getEntries()) {
                if (!timestampManifest.getEntries().contains(manifestEntry)) {
                    return false;
                }
                XmlManifestFile entryManifest = getCorrespondingManifestFile(manifestEntry);
                if (entryManifest != null) {
                    if (!checkManifestFilesCoveredRecursively(timestampManifest, entryManifest)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private boolean isAnyRootLevelDocumentCovered(XmlManifestFile timestampManifest) {
        List<String> rootLevelFiles = getRootLevelFiles(containerInfo.getContentFiles());
        return Utils.containsAny(timestampManifest.getEntries(), rootLevelFiles);
    }

    private XmlManifestFile getCorrespondingManifestFile(String filename) {
        for (XmlManifestFile manifestFile : containerInfo.getManifestFiles()) {
            if (filename.equals(manifestFile.getSignatureFilename())) {
                return manifestFile;
            }
        }
        return null;
    }

    private List<String> getRootLevelFiles(List<String> fileNames) {
        List<String> result = new ArrayList<>();
        for (String fileName : fileNames) {
            if (isRootDirectoryFile(fileName)) {
                result.add(fileName);
            }
        }
        return result;
    }

    private boolean isRootDirectoryFile(String fileName) {
        return !fileName.contains("/") && !fileName.contains("\\");
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_ISFP_ASTFORAMC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.FORMAT_FAILURE;
    }

}
