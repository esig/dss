/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.pades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.pdf.PDFTimestampService;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.PdfStream;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.DefaultAdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.ValidationContext;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation102853.crl.CRLToken;
import eu.europa.ec.markt.dss.validation102853.pades.PAdESSignature;
import eu.europa.ec.markt.dss.validation102853.pades.PDFDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * Extend a PAdES extension up to LTV.
 *
 * @version $Revision: 2723 $ - $Date: 2013-10-11 11:51:11 +0200 (Fri, 11 Oct 2013) $
 */

class PAdESLevelBaselineLT implements SignatureExtension {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBaselineLT.class);

    // DSSS/VRI dictionary is not mandatory, therefore it's not included
    // TODO: implementation of DSS/VRI is not complete
    private static final boolean INCLUDE_VRI_DICTIONARY = false;

    private final CertificateVerifier certificateVerifier;
    private final TSPSource tspSource;

    PAdESLevelBaselineLT(final TSPSource tspSource, final CertificateVerifier certificateVerifier) {

	    this.certificateVerifier = certificateVerifier;
        this.tspSource = tspSource;
    }

    /**
     * @param document
     * @param parameters
     * @return
     * @throws IOException
     */
    @Override
    public InMemoryDocument extendSignatures(DSSDocument document, final SignatureParameters parameters) throws DSSException {

	    try {

            // check if needed to extends with PAdESLevelBaselineT
            final PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
            pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
            List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();
            for (final AdvancedSignature signature : signatures) {

                if (!signature.isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_T)) {

                    document = new PAdESLevelBaselineT(tspSource, certificateVerifier).extendSignatures(document, parameters);
                    final PDFDocumentValidator pdfDocumentValidatorOverTimestamp = new PDFDocumentValidator(document);
                    pdfDocumentValidatorOverTimestamp.setCertificateVerifier(certificateVerifier);
                    signatures = pdfDocumentValidator.getSignatures();
                    break;
                }
            }

            assertExtendSignaturePossible(pdfDocumentValidator);

            for (final AdvancedSignature signature : signatures) {
                if (signature instanceof PAdESSignature) {
                    PAdESSignature pAdESSignature = (PAdESSignature) signature;
                    validate(pAdESSignature);
                }
            }

            final PdfObjFactory factory = PdfObjFactory.getInstance();
            PdfDict dssDictionary = factory.newDict("DSS");

            if (certArray.size() > 0) {
                dssDictionary.add("Certs", certArray);
            }

            if (crlArray.size() > 0) {
                dssDictionary.add("CRLs", crlArray);
            }

            if (ocspArray.size() > 0) {
                dssDictionary.add("OCSPs", ocspArray);
            }

            /**
             * Add the signature's VRI dictionary, hashing the signature block from the callback method.<br>
             * The key of each entry in this dictionary is the base-16-encoded (uppercase) SHA1 digest of the signature to
             * which it applies and the value is the Signature VRI dictionary which contains the validation-related
             * information for that signature.
             */
            if (INCLUDE_VRI_DICTIONARY) {
                // TODO: implementation of DSS/VRI is not complete
                PdfDict vriDictionary = factory.newDict("VRI");
                for (final AdvancedSignature signature : signatures) {
                    if (signature instanceof PAdESSignature) {
                        PdfDict sigVriDictionary = factory.newDict();
                        // sigVriDictionary to be completed with Cert, CRL and OCSP specific to this signature
                        PAdESSignature pAdESSignature = (PAdESSignature) signature;

                        final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, pAdESSignature.getCAdESSignature().getCmsSignedData().getEncoded());
                        String hexHash = DSSUtils.encodeHexString(digest).toUpperCase();

                        vriDictionary.add(hexHash, sigVriDictionary);

                    }
                }

                dssDictionary.add("VRI", vriDictionary);
                // Cert, CRL and OCSP to be included
            }

            /*
             Baseline LT: "Hence implementations claiming conformance to the LT-Conformance Level build the PAdES-LTV form
             (PAdES Part 4 [9], clause 4) on signatures that shall be compliant to the T-Level requirements and to the present
             clause."

             LTA: "It is recommended that signed PDF documents, conforming to this profile, contain DSS followed by a document Time-stamp."

             So we add a timestamp, and that a good thing because PDFBox cannot do incremental update without signing.
             */
            final ByteArrayOutputStream tDoc = new ByteArrayOutputStream();
            final PDFTimestampService timestampService = factory.newTimestampSignatureService();
            Map.Entry<String, PdfDict> dictToAdd = new AbstractMap.SimpleEntry<String, PdfDict>("DSS", dssDictionary);
            timestampService.timestamp(document, tDoc, parameters, tspSource, dictToAdd);
            return new InMemoryDocument(tDoc.toByteArray());

        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    private void assertExtendSignaturePossible(PDFDocumentValidator pdfDocumentValidator) {

    }

    // the information read from the signatures
    private PdfArray certArray = PdfObjFactory.getInstance().newArray();
    private PdfArray ocspArray = PdfObjFactory.getInstance().newArray();
    private PdfArray crlArray = PdfObjFactory.getInstance().newArray();

    private void validate(final PAdESSignature pAdESSignature) {

        try {
            final CAdESSignature cadesSignature = pAdESSignature.getCAdESSignature();
            final ValidationContext validationContext = cadesSignature.getSignatureValidationContext(certificateVerifier);
            final DefaultAdvancedSignature.RevocationDataForInclusion revocationsForInclusionInProfileLT = cadesSignature.getRevocationDataForInclusion(validationContext);

            for (final CRLToken crlToken : revocationsForInclusionInProfileLT.crlTokens) {
                final PdfStream stream = PdfObjFactory.getInstance().newStream(crlToken.getEncoded());
                crlArray.add(stream);

            }
            for (final OCSPToken ocspToken : revocationsForInclusionInProfileLT.ocspTokens) {
                final PdfStream stream = PdfObjFactory.getInstance().newStream(ocspToken.getEncoded());
                ocspArray.add(stream);
            }

            final Set<CertificateToken> certificatesForInclusionInProfileLT = cadesSignature.getCertificatesForInclusion(validationContext);
            for (final CertificateToken certificateToken : certificatesForInclusionInProfileLT) {
                final PdfStream stream = PdfObjFactory.getInstance().newStream(certificateToken.getEncoded());
                certArray.add(stream);
            }
        } catch (IOException e) {
            throw new DSSException(e);
        }

        //TODO (nicolas pdfbox): missing looking into PADES document-timestamp to add CRL/OCSP/Certificates ?. (Some of these timestamp are included in the cadesSignaure , but not the document-timestamp)

    }

}
