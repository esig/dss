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
package eu.europa.esig.dss.xades.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;
import eu.europa.esig.dss.spi.validation.evidencerecord.AbstractEmbeddedEvidenceRecordHelper;
import eu.europa.esig.dss.spi.validation.evidencerecord.SignatureEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.xades.validation.XAdESAttribute;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

/**
 * This class contains common methods for validation of a XAdES embedded evidence record
 *
 */
public class XAdESEmbeddedEvidenceRecordHelper extends AbstractEmbeddedEvidenceRecordHelper {

    /**
     * Constructor for an evidence record applied for the whole signature content (not yet embedded)
     *
     * @param signature {@link XAdESSignature}
     */
    public XAdESEmbeddedEvidenceRecordHelper(final XAdESSignature signature) {
        super(signature);
    }

    /**
     * Default constructor
     *
     * @param signature {@link XAdESSignature}
     * @param evidenceRecordAttribute {@link XAdESAttribute}
     */
    public XAdESEmbeddedEvidenceRecordHelper(final XAdESSignature signature,
                                             final XAdESAttribute evidenceRecordAttribute) {
        super(signature, evidenceRecordAttribute);
    }

    @Override
    protected SignatureEvidenceRecordDigestBuilder getDigestBuilder(AdvancedSignature signature,
            SignatureAttribute evidenceRecordAttribute, DigestAlgorithm digestAlgorithm) {
        XAdESEvidenceRecordDigestBuilder digestBuilder = new XAdESEvidenceRecordDigestBuilder(signature, evidenceRecordAttribute, digestAlgorithm);
        digestBuilder.setDetachedContent(getDetachedContents());
        return digestBuilder;
    }

    @Override
    protected void setDEREncoding(SignatureEvidenceRecordDigestBuilder digestBuilder, boolean derEncoded) {
        throw new UnsupportedOperationException(
                "The #setEncoding method is not supported for a XAdES signature digest computation!");
    }

    @Override
    public boolean isEncodingSelectionSupported() {
        return false;
    }

}
