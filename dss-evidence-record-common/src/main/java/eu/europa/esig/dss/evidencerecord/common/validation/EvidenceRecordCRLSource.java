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
package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Extracts and returns CRL tokens embedded within an Evidence Record structure
 *
 */
public class EvidenceRecordCRLSource extends OfflineCRLSource {

    private static final long serialVersionUID = -8846746778038286512L;

    private static final Logger LOG = LoggerFactory.getLogger(EvidenceRecordCRLSource.class);

    /**
     * List of {@code ArchiveTimeStampChainObject} representing a structure of an Evidence Record
     */
    private final List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence;

    /**
     * Default constructor
     *
     * @param archiveTimeStampSequence a list of {@link ArchiveTimeStampChainObject}s
     */
    public EvidenceRecordCRLSource(final List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence) {
        this.archiveTimeStampSequence = archiveTimeStampSequence;
        extractCRLs();
    }

    private void extractCRLs() {
        if (Utils.isCollectionEmpty(archiveTimeStampSequence)) {
            return;
        }
        for (ArchiveTimeStampChainObject archiveTimeStampChainObject : archiveTimeStampSequence) {
            List<? extends ArchiveTimeStampObject> archiveTimeStamps = archiveTimeStampChainObject.getArchiveTimeStamps();
            if (Utils.isCollectionNotEmpty(archiveTimeStamps)) {
                for (ArchiveTimeStampObject archiveTimeStampObject : archiveTimeStamps) {
                    List<CryptographicInformation> cryptographicInformationList = archiveTimeStampObject.getCryptographicInformationList();
                    if (Utils.isCollectionNotEmpty(cryptographicInformationList)) {
                        for (CryptographicInformation cryptographicInformation : cryptographicInformationList) {
                            if (CryptographicInformationType.CRL.equals(cryptographicInformation.getType())) {
                                byte[] derEncoded = cryptographicInformation.getContent();
                                try {
                                    CRLBinary crlBinary = CRLUtils.buildCRLBinary(derEncoded);
                                    addBinary(crlBinary, RevocationOrigin.EVIDENCE_RECORD);
                                } catch (Exception e) {
                                    LOG.warn("Unable to parse CRL '{}' : {}", Utils.toBase64(derEncoded), e.getMessage(), e);
                                }
                            }
                        }
                    }
                }
            }
        }
        if (LOG.isInfoEnabled()) {
            LOG.info("+EvidenceRecordCertificateSource");
        }
    }

}
