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
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordRenewalDigestBuilderHelper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilder;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Verifies ArchiveTimeStampSequence for an XML Evidence Record
 *
 */
public class XmlEvidenceRecordTimeStampSequenceVerifier extends EvidenceRecordTimeStampSequenceVerifier {

    /**
     * Default constructor to instantiate an XML evidence record verifier
     *
     * @param evidenceRecord {@link XmlEvidenceRecord} XML evidence record to be validated
     */
    public XmlEvidenceRecordTimeStampSequenceVerifier(XmlEvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    protected DataObjectDigestBuilder getDataObjectDigestBuilder(DSSDocument document, ArchiveTimeStampChainObject archiveTimeStampChain) {
        DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();
        String canonicalizationMethod = getCanonicalizationMethod(archiveTimeStampChain);
        return new XMLEvidenceRecordDataObjectDigestBuilder(document, digestAlgorithm)
                .setCanonicalizationMethod(canonicalizationMethod);
    }

    /**
     * Extracts a canonicalization method defined within XML {@code ArchiveTimeStampChainObject}
     *
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} to get canonicalization method definition from
     * @return {@link String} canonicalization method
     */
    protected String getCanonicalizationMethod(ArchiveTimeStampChainObject archiveTimeStampChain) {
        XmlArchiveTimeStampChainObject xmlArchiveTimeStampChainObject = (XmlArchiveTimeStampChainObject) archiveTimeStampChain;
        return xmlArchiveTimeStampChainObject.getCanonicalizationMethod();
    }

    @Override
    protected List<? extends DigestValueGroup> getHashTree(
            List<? extends DigestValueGroup> originalHashTree, List<DSSDocument> detachedContents, ManifestFile manifestFile,
            ArchiveTimeStampChainObject archiveTimeStampChain, DSSMessageDigest lastTimeStampHash, DSSMessageDigest lastTimeStampSequenceHash) {
        final List<? extends DigestValueGroup> hashTree = super.getHashTree(
                originalHashTree, detachedContents, manifestFile, archiveTimeStampChain, lastTimeStampHash, lastTimeStampSequenceHash);

        // HashTree renewal time-stamp shall cover one or more data objects
        if (lastTimeStampSequenceHash != null && !lastTimeStampSequenceHash.isEmpty()) {
            DigestValueGroup firstDigestValueGroup = hashTree.get(0);
            if (Utils.collectionSize(firstDigestValueGroup.getDigestValues()) == 1) {
                List<byte[]> newDigestValuesGroup = new ArrayList<>(firstDigestValueGroup.getDigestValues());
                newDigestValuesGroup.add(DSSUtils.EMPTY_BYTE_ARRAY);
                firstDigestValueGroup.setDigestValues(newDigestValuesGroup);
            }
        }

        return hashTree;
    }

    @Override
    protected DSSMessageDigest computeTimeStampHash(ArchiveTimeStampObject archiveTimeStamp) {
        return getEvidenceRecordRenewalDigestBuilderHelper().buildTimeStampRenewalDigest(archiveTimeStamp);
    }

    @Override
    protected DSSMessageDigest computeTimeStampSequenceHash(ArchiveTimeStampChainObject archiveTimeStampChain) {
        return getEvidenceRecordRenewalDigestBuilderHelper().buildArchiveTimeStampSequenceDigest(archiveTimeStampChain);
    }

    /**
     * This method returns a helper class containing supporting methods for digest computation in relation
     * to an ArchiveTimeStampChain
     *
     * @return {@link XMLEvidenceRecordRenewalDigestBuilderHelper}
     */
    protected XMLEvidenceRecordRenewalDigestBuilderHelper getEvidenceRecordRenewalDigestBuilderHelper() {
        return new XMLEvidenceRecordRenewalDigestBuilderHelper((XmlEvidenceRecord) evidenceRecord);
    }

}
