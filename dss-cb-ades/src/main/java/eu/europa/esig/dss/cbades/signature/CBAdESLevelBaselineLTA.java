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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.CBAdESUtils;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeaders;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

/**
 * This class provides a functionality for the CB-AdES-BASELINE-LTA profile augmentation.
 *
 */
public class CBAdESLevelBaselineLTA extends CBAdESLevelBaselineLT {

    /**
     * The default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier} to use
     */
    public CBAdESLevelBaselineLTA(CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
    }

    @Override
    protected void extendSignatures(List<AdvancedSignature> signatures, CBAdESSignatureParameters params) {
        super.extendSignatures(signatures, params);

        final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker(params);
        signatureRequirementsChecker.assertSignaturesValid(signatures);

        boolean addTimestampValidationData = false;

        for (AdvancedSignature signature : signatures) {
            CBAdESSignature jadesSignature = (CBAdESSignature) signature;
            assertExtendSignatureToLTAPossible(jadesSignature, params);

            if (jadesSignature.hasLTAProfile()) {
                addTimestampValidationData = true;
            }
        }

        // Perform signature validation
        ValidationDataContainer validationDataContainer = null;
        if (addTimestampValidationData) {
            validationDataContainer = getValidationData(signatures, params);
        }

        for (AdvancedSignature signature : signatures) {
            CBAdESSignature cbadesSignature = (CBAdESSignature) signature;
            CBAdESUHeaders uHeaders = cbadesSignature.getUHeaders();

            if (cbadesSignature.hasLTAProfile() && addTimestampValidationData) {
                removeLastValidationData(cbadesSignature, uHeaders);

                final ValidationData validationDataForInclusion =
                        validationDataContainer.getAllValidationDataForSignatureForInclusion(signature);
                if (!validationDataForInclusion.isEmpty()) {
                    CBORValue valData = getValData(validationDataForInclusion);
                    uHeaders.addComponent(COSEHeaderParameter.VAL_DATA.cbor(), valData);
                }
            }

            TimestampBinary timestampBinary = getArchiveTimestamp(cbadesSignature, params);
            CBORValue tstContainer = CBAdESUtils.getTstContainer(Collections.singletonList(timestampBinary));
            uHeaders.addComponent(COSEHeaderParameter.ARC_TST.cbor(), tstContainer);
        }
    }

    /**
     * Removes the last 'valData' component, when present
     *
     * @param cbadesSignature {@link CBAdESSignature} being augmented
     * @param uHeaders {@link CBAdESUHeaders}
     */
    private void removeLastValidationData(CBAdESSignature cbadesSignature, CBAdESUHeaders uHeaders) {
        uHeaders.removeLastComponent(COSEHeaderParameter.VAL_DATA.cbor());
        cbadesSignature.resetCertificateSource();
        cbadesSignature.resetRevocationSources();
    }

    private TimestampBinary getArchiveTimestamp(CBAdESSignature cbadesSignature, CBAdESSignatureParameters params) {
        CBAdESTimestampParameters archiveTimestampParameters = params.getArchiveTimestampParameters();
        DigestAlgorithm digestAlgorithmForTimestampRequest = archiveTimestampParameters.getDigestAlgorithm();

        final DSSMessageDigest messageDigest = cbadesSignature.getTimestampSource()
                .getArchiveTimestampData(digestAlgorithmForTimestampRequest);
        return tspSource.getTimeStampResponse(digestAlgorithmForTimestampRequest, messageDigest.getValue());
    }

    /**
     * Checks if the extension is possible.
     */
    private void assertExtendSignatureToLTAPossible(CBAdESSignature cbadesSignature, CBAdESSignatureParameters params) {
        assertDetachedDocumentsContainBinaries(params);
        assertUHeadersComponentsConsistent(cbadesSignature);
    }

    private void assertDetachedDocumentsContainBinaries(CBAdESSignatureParameters params) {
        List<DSSDocument> detachedContents = params.getDetachedContents();
        if (Utils.isCollectionNotEmpty(detachedContents)) {
            for (DSSDocument detachedDocument : detachedContents) {
                if (detachedDocument instanceof DigestDocument) {
                    throw new IllegalArgumentException("CB-AdES-BASELINE-LTA requires complete binaries of signed documents! "
                            + "Extension with a DigestDocument is not possible.");
                }
            }
        }
    }
    
}
