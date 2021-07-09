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
package eu.europa.esig.dss.pades.validation.timestamp;

import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.timestamp.CAdESTimestampSource;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfDssDictCRLSource;
import eu.europa.esig.dss.pades.validation.PdfDssDictCertificateSource;
import eu.europa.esig.dss.pades.validation.PdfDssDictOCSPSource;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.RevocationInfoArchival;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static eu.europa.esig.dss.spi.OID.adbe_revocationInfoArchival;

@SuppressWarnings("serial")
public class PAdESTimestampSource extends CAdESTimestampSource {

    private final transient List<PdfRevision> documentRevisions;

    /**
     * This variable contains the list of embedded document timestamps.
     */
    protected List<TimestampToken> documentTimestamps;

    /**
     * The default constructor to extract timestamps for a signature
     *
     * @param signature {@link PAdESSignature} to extract timestamps for
     * @param documentRevisions a list of document {@link PdfRevision}s
     */
    public PAdESTimestampSource(final PAdESSignature signature, final List<PdfRevision> documentRevisions) {
        super(signature);
        Objects.requireNonNull(documentRevisions, "List of Document revisions must be provided!");
        this.documentRevisions = Utils.reverseList(documentRevisions);
    }

    @Override
    public List<TimestampToken> getDocumentTimestamps() {
        if (documentTimestamps == null) {
            createAndValidate();
        }
        return documentTimestamps;
    }

    @Override
    protected PAdESTimestampDataBuilder getTimestampDataBuilder() {
        PAdESTimestampDataBuilder padesTimestampDataBuilder = new PAdESTimestampDataBuilder(
                documentRevisions, (PAdESSignature) signature, certificateSource);
        padesTimestampDataBuilder.setSignatureTimestamps(getSignatureTimestamps());
        return padesTimestampDataBuilder;
    }

    @Override
    protected void makeTimestampTokensFromSignedAttributes() {
        if (signature != null) {
            super.makeTimestampTokensFromSignedAttributes();
        }
    }

    @Override
    protected void makeTimestampTokensFromUnsignedAttributes() {
        // Creates signature timestamp tokens only (from CAdESTimestampSource)
        super.makeTimestampTokensFromUnsignedAttributes();

        final List<TimestampToken> cadesSignatureTimestamps = getSignatureTimestamps();
        final List<TimestampToken> timestampedTimestamps = new ArrayList<>(cadesSignatureTimestamps);

        // store all found references
        unsignedPropertiesReferences = new ArrayList<>();

        // contains the list of PDF timestamps
        documentTimestamps = new ArrayList<>();

        boolean signatureRevisionReached = false;
        boolean dssRevisionReached = false;

        for (final PdfRevision pdfRevision : documentRevisions) {

            if (pdfRevision instanceof PdfDocTimestampRevision) {
                // lists are separated in order to distinguish sources between different timestamps
                List<TimestampedReference> individualTimestampReferences = new ArrayList<>();

                final PdfDocTimestampRevision timestampRevision = (PdfDocTimestampRevision) pdfRevision;
                final TimestampToken timestampToken = timestampRevision.getTimestampToken();

                if (dssRevisionReached) {
                    timestampToken.setArchiveTimestampType(ArchiveTimestampType.PAdES);
                }
                if (signatureRevisionReached) {
                    addReferences(individualTimestampReferences, getSignatureTimestampReferences());
                    addReferences(individualTimestampReferences, getSignatureSignedDataReferences());
                }
                if (Utils.isCollectionNotEmpty(unsignedPropertiesReferences)) {
                    // covers DSS dictionary
                    addReferences(individualTimestampReferences, unsignedPropertiesReferences);
                }
                addReferences(individualTimestampReferences, getEncapsulatedReferencesFromTimestamps(timestampedTimestamps));

                // references embedded to timestamp's content are covered by outer timestamps
                addReferences(timestampToken.getTimestampedReferences(), individualTimestampReferences);

                if (signatureRevisionReached) {
                    documentTimestamps.add(timestampToken);
                }

                populateSources(timestampToken);
                timestampedTimestamps.add(timestampToken);

            } else if (pdfRevision instanceof PdfDocDssRevision) {
                PdfDocDssRevision pdfDocDssRevision = (PdfDocDssRevision) pdfRevision;
                PdfRevisionTimestampSource pdfRevisionTimestampSource = new PdfRevisionTimestampSource(pdfDocDssRevision);
                addReferences(unsignedPropertiesReferences, pdfRevisionTimestampSource.getIncorporatedReferences());

                PdfDssDict dssDictionary = pdfDocDssRevision.getDssDictionary();
                certificateSource.add(new PdfDssDictCertificateSource(dssDictionary));
                crlSource.add(new PdfDssDictCRLSource(dssDictionary));
                ocspSource.add(new PdfDssDictOCSPSource(dssDictionary));
                dssRevisionReached = true;

            } else if (pdfRevision instanceof PdfSignatureRevision) {
                PAdESSignature padesSignature = (PAdESSignature) signature;
                if (padesSignature.getPdfRevision() == pdfRevision) {
                    signatureRevisionReached = true;
                }

            }
        }
    }

    @Override
    protected boolean isCompleteCertificateRef(CAdESAttribute unsignedAttribute) {
        // not applicable for PAdES
        return false;
    }

    @Override
    protected boolean isAttributeCertificateRef(CAdESAttribute unsignedAttribute) {
        // not applicable for PAdES
        return false;
    }

    @Override
    protected boolean isCompleteRevocationRef(CAdESAttribute unsignedAttribute) {
        // not applicable for PAdES
        return false;
    }

    @Override
    protected boolean isAttributeRevocationRef(CAdESAttribute unsignedAttribute) {
        // not applicable for PAdES
        return false;
    }

    @Override
    protected boolean isRefsOnlyTimestamp(CAdESAttribute unsignedAttribute) {
        // not applicable for PAdES
        return false;
    }

    @Override
    protected boolean isSigAndRefsTimestamp(CAdESAttribute unsignedAttribute) {
        // not applicable for PAdES
        return false;
    }

    @Override
    protected boolean isCertificateValues(CAdESAttribute unsignedAttribute) {
        // not applicable for PAdES
        return false;
    }

    @Override
    protected boolean isRevocationValues(CAdESAttribute unsignedAttribute) {
        // not applicable for PAdES
        return false;
    }

    @Override
    protected boolean isArchiveTimestamp(CAdESAttribute unsignedAttribute) {
        // not applicable for PAdES
        return false;
    }

    @Override
    protected List<TimestampedReference> getSignatureTimestampReferences() {
        List<TimestampedReference> signatureTimestampReferences = super.getSignatureTimestampReferences();
        addReferences(signatureTimestampReferences,
                createReferencesForIdentifiers(getAdbeRevocationInfoArchivalReferences(), TimestampedObjectType.REVOCATION));
        return signatureTimestampReferences;
    }

    /**
     * Returns a list of revocation data identifiers from the adbe-revocationInfoArchival signed attribute
     *
     * @return a list of {@link Identifier}s
     */
    protected List<Identifier> getAdbeRevocationInfoArchivalReferences() {
        SignatureProperties<CAdESAttribute> signedSignatureProperties = getSignedSignatureProperties();
        if (!signedSignatureProperties.isExist()) {
            return Collections.emptyList();
        }
        final List<Identifier> identifiers = new ArrayList<>();
        for (CAdESAttribute attribute : signedSignatureProperties.getAttributes()) {
            if (isAdbeRevocationInfoArchival(attribute)) {
                RevocationInfoArchival revValues = PAdESUtils.getRevocationInfoArchival(attribute.getASN1Object());
                if (revValues != null) {
                    identifiers.addAll(buildCRLIdentifiers(revValues.getCrlVals()));
                    identifiers.addAll(buildOCSPIdentifiers(DSSASN1Utils.toBasicOCSPResps(revValues.getOcspVals())));
                }
            }
        }
        return identifiers;
    }

    /**
     * Checks if the {@code signedAttribute} is an instance of type adbe-revocationInfoArchival
     *
     * @param signedAttribute {@link CAdESAttribute} to check
     * @return TRUE if the attribute is an instance of type adbe-revocationInfoArchival, FALSE otherwise
     */
    protected boolean isAdbeRevocationInfoArchival(CAdESAttribute signedAttribute) {
        return adbe_revocationInfoArchival.equals(signedAttribute.getASN1Oid());
    }

    @Override
    protected List<AdvancedSignature> getCounterSignatures(CAdESAttribute unsignedAttribute) {
        // not supported in PAdES
        return Collections.emptyList();
    }

}
