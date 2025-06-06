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
package eu.europa.esig.dss.cades.evidencerecord;

import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;
import eu.europa.esig.dss.spi.validation.evidencerecord.AbstractEmbeddedEvidenceRecordHelper;
import eu.europa.esig.dss.spi.validation.evidencerecord.SignatureEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * This class contains common methods for validation of a CAdES embedded evidence record
 *
 */
public class CAdESEmbeddedEvidenceRecordHelper extends AbstractEmbeddedEvidenceRecordHelper {

    private static final Logger LOG = LoggerFactory.getLogger(CAdESEmbeddedEvidenceRecordHelper.class);

    /**
     * Constructor for an evidence record applied for the whole signature content (not yet embedded)
     *
     * @param signature {@link CAdESSignature}
     */
    public CAdESEmbeddedEvidenceRecordHelper(final CAdESSignature signature) {
        super(signature);
    }

    /**
     * Default constructor
     *
     * @param signature {@link CAdESSignature}
     * @param evidenceRecordAttribute {@link CAdESAttribute}
     */
    public CAdESEmbeddedEvidenceRecordHelper(final CAdESSignature signature,
                                             final CAdESAttribute evidenceRecordAttribute) {
        super(signature, evidenceRecordAttribute);
    }

    @Override
    public void setDetachedContents(List<DSSDocument> detachedContents) {
        if (Utils.collectionSize(detachedContents) != 1) {
            throw new IllegalArgumentException("One and only one detached document is allowed for an embedded evidence record in CAdES!");
        }
        super.setDetachedContents(detachedContents);
    }

    @Override
    protected SignatureEvidenceRecordDigestBuilder getDigestBuilder(AdvancedSignature signature,
                                                                    SignatureAttribute evidenceRecordAttribute, DigestAlgorithm digestAlgorithm) {
        CAdESEvidenceRecordDigestBuilder digestBuilder = new CAdESEvidenceRecordDigestBuilder(signature, evidenceRecordAttribute, digestAlgorithm);
        if (isDetached(signature)) {
            digestBuilder.setDetachedContent(getDetachedDocument());
        }
        return digestBuilder;
    }

    private boolean isDetached(AdvancedSignature signature) {
        if (signature instanceof CAdESSignature) {
            return ((CAdESSignature) signature).getCMS().isDetachedSignature();
        }
        throw new IllegalStateException("Only instance of CAdESSignature is supported by CAdESEmbeddedEvidenceRecordHelper");
    }

    /**
     * Gets the detached document covered by a detached CAdES
     *
     * @return {@link DSSDocument}
     */
    protected DSSDocument getDetachedDocument() {
        List<DSSDocument> detachedContents = getDetachedContents();
        if (Utils.collectionSize(detachedContents) == 1) {
            return detachedContents.get(0);
        }
        return null;
    }

    @Override
    protected void setDEREncoding(SignatureEvidenceRecordDigestBuilder digestBuilder, boolean derEncoded) {
        if (digestBuilder instanceof CAdESEvidenceRecordDigestBuilder) {
            CAdESEvidenceRecordDigestBuilder cadesEvidenceRecordDigestBuilder = (CAdESEvidenceRecordDigestBuilder) digestBuilder;
            cadesEvidenceRecordDigestBuilder.setDEREncoded(derEncoded);
        } else {
            throw new IllegalArgumentException("The digestBuilder shall be an instance of CAdESEvidenceRecordDigestBuilder!");
        }
    }

    @Override
    public boolean isEncodingSelectionSupported() {
        return true;
    }

}
