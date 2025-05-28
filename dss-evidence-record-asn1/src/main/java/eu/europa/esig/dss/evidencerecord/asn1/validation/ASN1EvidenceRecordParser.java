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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampIdentifierBuilder;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.evidencerecord.EmbeddedEvidenceRecordHelper;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This class is used to parse an ASN.1 Evidence Record
 *
 */
public class ASN1EvidenceRecordParser implements EvidenceRecordParser {
	
	private static final Logger LOG = LoggerFactory.getLogger(ASN1EvidenceRecordParser.class);

    /** The BouncyCastle evidence record object to be parsed */
    private final EvidenceRecord evidenceRecord;

    /** The name of the file document containing the evidence record */
    private String filename;

    /** Optional attribute used for processing of embedded evidence records */
    private EmbeddedEvidenceRecordHelper embeddedEvidenceRecordHelper;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    public ASN1EvidenceRecordParser(final EvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Sets a filename of the document containing the evidence record
     *
     * @param filename {@link String}
     * @return this {@link ASN1EvidenceRecordParser}
     */
    public ASN1EvidenceRecordParser setFilename(String filename) {
        this.filename = filename;
        return this;
    }

    /**
     * Sets a helper for processing of embedded evidence records
     *
     * @param embeddedEvidenceRecordHelper {@link EmbeddedEvidenceRecordHelper}
     * @return this {@link ASN1EvidenceRecordParser}
     */
    public ASN1EvidenceRecordParser setEmbeddedEvidenceRecordHelper(EmbeddedEvidenceRecordHelper embeddedEvidenceRecordHelper) {
        this.embeddedEvidenceRecordHelper = embeddedEvidenceRecordHelper;
        return this;
    }

    /**
     * Parses the XML Evidence Record object and returns a list of {@code ArchiveTimeStampChainObject}s
     * representing an archive time-stamp sequence
     *
     * @return a list of {@code ArchiveTimeStampChainObject}s
     */
    @Override
    public List<ASN1ArchiveTimeStampChainObject> parse() {
    	ArchiveTimeStampSequence archiveTimeStampSequenceList = this.evidenceRecord.getArchiveTimeStampSequence();
        if (archiveTimeStampSequenceList != null && archiveTimeStampSequenceList.size() > 0) {
        	ASN1ArchiveTimeStampChainObject[] result = new ASN1ArchiveTimeStampChainObject[archiveTimeStampSequenceList.size()];
            for (int i = 0; i < archiveTimeStampSequenceList.size(); i++) {
                final ArchiveTimeStampChain archiveTimeStampChain = archiveTimeStampSequenceList.getArchiveTimeStampChains()[i];
                ASN1ArchiveTimeStampChainObject archiveTimeStampChainObject = getASN1ArchiveTimeStampChainObject(archiveTimeStampChain, i+1);
                result[i] = archiveTimeStampChainObject;
            }
            return Arrays.asList(result);
        }

        return Collections.emptyList();
    }
    
    private ASN1ArchiveTimeStampChainObject getASN1ArchiveTimeStampChainObject(ArchiveTimeStampChain archiveTimeStampChain, int order) {
    	ASN1ArchiveTimeStampChainObject archiveTimeStampChainObject = new ASN1ArchiveTimeStampChainObject();
        archiveTimeStampChainObject.setDigestAlgorithm(getDigestAlgorithm(archiveTimeStampChain));
        archiveTimeStampChainObject.setOrder(order);
        archiveTimeStampChainObject.setArchiveTimeStamps(getASN1ArchiveTimeStamps(archiveTimeStampChain, order));
        return archiveTimeStampChainObject;
    }
    
    private DigestAlgorithm getDigestAlgorithm(ArchiveTimeStampChain archiveTimeStampChain) {
        /*
         * 5. Archive Timestamp Chain and Archive Timestamp Sequence (5.2. Generation)
         *
         * The new Archive Timestamp MUST be added to the ArchiveTimestampChain.
         * This hash tree of the new Archive Timestamp MUST use the same hash algorithm as the old one,
         * which is specified in the digestAlgorithm field of the Archive Timestamp or,
         * if this value is not set (as it is optional), within the timestamp itself.
         */
        // return the first value
        return getDigestAlgorithm(archiveTimeStampChain.getArchiveTimestamps()[0]);
    }

    private List<? extends ArchiveTimeStampObject> getASN1ArchiveTimeStamps(ArchiveTimeStampChain archiveTimeStampChain, int archiveTimeStampChainOrder) {
        final ArchiveTimeStamp[] archiveTimeStampList = archiveTimeStampChain.getArchiveTimestamps();
        if (archiveTimeStampList != null && archiveTimeStampList.length > 0) {
        	ASN1ArchiveTimeStampObject[] result = new ASN1ArchiveTimeStampObject[archiveTimeStampList.length];
            for (int i = 0; i < archiveTimeStampList.length; i++) {
                final ArchiveTimeStamp archiveTimeStamp = archiveTimeStampList[i];
                ASN1ArchiveTimeStampObject archiveTimeStampObject = getASN1ArchiveTimeStampObject(archiveTimeStamp, archiveTimeStampChainOrder, i+1);
                result[i] = archiveTimeStampObject;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }
    
    private ASN1ArchiveTimeStampObject getASN1ArchiveTimeStampObject(ArchiveTimeStamp archiveTimeStamp, int archiveTimeStampChainOrder, int archiveTimeStampOrder) {
    	ASN1ArchiveTimeStampObject archiveTimeStampObject = new ASN1ArchiveTimeStampObject();
        archiveTimeStampObject.setHashTree(getHashTree(archiveTimeStamp));
        archiveTimeStampObject.setDigestAlgorithm(getDigestAlgorithm(archiveTimeStamp));
        archiveTimeStampObject.setTimestampToken(getTimestampToken(archiveTimeStamp, archiveTimeStampChainOrder, archiveTimeStampOrder));
        archiveTimeStampObject.setOrder(archiveTimeStampOrder);
        // cryptographic info not applicable for ANS.1
        return archiveTimeStampObject;
    }

    private DigestAlgorithm getDigestAlgorithm(ArchiveTimeStamp archiveTimeStamp) {
        /*
         * digestAlgorithm identifies the digest algorithm and any associated
         * parameters used within the reduced hash tree. If the optional field
         * digestAlgorithm is not present, the digest algorithm of the timestamp
         * MUST be used. Which means, if timestamps according to [RFC3161] are
         * hashAlgorithm of messageImprint field of TSTInfo.
         */
        // NOTE: BouncyCastle implements the logic itself within getDigestAlgorithmIdentifier() method
        AlgorithmIdentifier algIdentifier = archiveTimeStamp.getDigestAlgorithmIdentifier();
        return DigestAlgorithm.forOID(algIdentifier.getAlgorithm().getId());
    }
    
    private TimestampToken getTimestampToken(ArchiveTimeStamp archiveTimeStamp, int archiveTimeStampChainOrder, int archieTimeStampOrder) {
    	ContentInfo contentInfo = archiveTimeStamp.getTimeStamp();
        if (contentInfo == null) {
            throw new IllegalInputException("TimeStampToken shall be defined!");
        }
        try {
            byte[] timestampBinaries = contentInfo.getEncoded();
            EvidenceRecordTimestampIdentifierBuilder identifierBuilder = new EvidenceRecordTimestampIdentifierBuilder(timestampBinaries)
                    .setArchiveTimeStampChainOrder(archiveTimeStampChainOrder)
                    .setArchiveTimeStampOrder(archieTimeStampOrder)
                    .setFilename(filename);
            if (embeddedEvidenceRecordHelper != null) {
                identifierBuilder = identifierBuilder
                        .setEvidenceRecordAttributeOrder(embeddedEvidenceRecordHelper.getOrderOfAttribute())
                        .setEvidenceRecordWithinAttributeOrder(embeddedEvidenceRecordHelper.getOrderWithinAttribute());
            }
            return new TimestampToken(timestampBinaries, TimestampType.EVIDENCE_RECORD_TIMESTAMP, new ArrayList<>(), identifierBuilder);
        } catch (Exception e) {
            LOG.warn("Unable to create a time-stamp token. Reason : {}", e.getMessage(), e);
            return null;
        }
    }
    
    private List<ASN1SequenceObject> getHashTree(ArchiveTimeStamp archiveTimeStamp) {
        final PartialHashtree[] hashTree = archiveTimeStamp.getReducedHashTree();
        if (hashTree != null && hashTree.length > 0) {
        	ASN1SequenceObject[] result = new ASN1SequenceObject[hashTree.length];
            for (int i = 0; i < hashTree.length; i++) {
                final PartialHashtree partialHashtree = hashTree[i];
                ASN1SequenceObject digestValueGroup = getDigestValueGroup(partialHashtree, i+1);
                result[i] = digestValueGroup;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }

    private ASN1SequenceObject getDigestValueGroup(PartialHashtree partialHashtree, int order) {
    	ASN1SequenceObject digestValueGroup = new ASN1SequenceObject();
        digestValueGroup.setDigestValues(getDigestValues(partialHashtree));
        digestValueGroup.setOrder(order);
        return digestValueGroup;
    }
    
    private List<byte[]> getDigestValues(PartialHashtree partialHashtree) {
        List<byte[]> result = new ArrayList<>();

        final byte[][] digestValueList = partialHashtree.getValues();
        for (int i = 0; i < partialHashtree.getValueCount(); i++) {
            final byte[] digestValue = digestValueList[i];
            result.add(digestValue);
        }

        return result;
    }

}
