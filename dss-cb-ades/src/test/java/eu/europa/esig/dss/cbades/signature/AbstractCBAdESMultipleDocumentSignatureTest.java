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
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSESign;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.COSEUnprotectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.validation.CBAdESCertificateSource;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeaders;
import eu.europa.esig.dss.cbades.validation.CBORSignature;
import eu.europa.esig.dss.cbades.validation.COSEDocumentValidator;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.BaselineBCertificateSelector;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestMultipleDocumentsSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractCBAdESMultipleDocumentSignatureTest extends
        AbstractPkiFactoryTestMultipleDocumentsSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> {

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        DSSDocument signedDocument = new InMemoryDocument(byteArray);
        assertTrue(COSEParser.isSupported(signedDocument));

        COSEParser coseParser = COSEParser.fromDocument(signedDocument);
        COSESignStructure coseSignStructure = coseParser.parse();
        checkCOSESignStructure(coseSignStructure);
    }

    protected void checkCOSESignStructure(COSESignStructure coseSignStructure) {
        assertNotNull(coseSignStructure);

        assertNotNull(coseSignStructure.getContext());

        assertEquals(COSEStructureType.COSE_SIGN == getSignatureParameters().getCoseStructureType(),
                coseSignStructure instanceof COSESign);
        assertEquals(COSEStructureType.COSE_SIGN1 == getSignatureParameters().getCoseStructureType(),
                coseSignStructure instanceof COSESign1);

        boolean isTagged = Utils.isTrue(getSignatureParameters().isTagged()) || getSignatureParameters().isTagged() == null;
        assertEquals(isTagged, coseSignStructure.isTagged());

        assertNotNull(coseSignStructure.getPayload());
        assertEquals(SignaturePackaging.DETACHED == getSignatureParameters().getSignaturePackaging(), coseSignStructure.getPayload().isNull());
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        COSEDocumentValidator documentValidator = (COSEDocumentValidator) super.getValidator(signedDocument);
        documentValidator.setExternallySuppliedData(getExternallySuppliedData());
        return documentValidator;
    }

    protected DSSDocument getExternallySuppliedData() {
        return null;
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        for (AdvancedSignature signature : signatures) {
            assertInstanceOf(CBAdESSignature.class, signature);
            CBAdESSignature cbadesSignature = (CBAdESSignature) signature;

            CBORSignature cose = cbadesSignature.getCoseSignature();

            CBAdESUHeaders cbAdESUHeaders = new CBAdESUHeaders(cose);
            assertEquals(cbAdESUHeaders.isExist(), !SignatureLevel.CB_AdES_BASELINE_B.equals(getSignatureParameters().getSignatureLevel()));

            assertNotNull(cose.getContext());
            assertEquals(COSEStructureType.COSE_SIGN == getSignatureParameters().getCoseStructureType(),
                    COSESignatureType.COSE_SIGN == cose.getContext());
            assertEquals(COSEStructureType.COSE_SIGN1 == getSignatureParameters().getCoseStructureType(),
                    COSESignatureType.COSE_SIGN1 == cose.getContext());

            assertNotNull(cose.getCoseSignStructure());
            assertEquals(COSEStructureType.COSE_SIGN == getSignatureParameters().getCoseStructureType(),
                    cose.getCoseSignStructure() instanceof COSESign);
            assertEquals(COSEStructureType.COSE_SIGN1 == getSignatureParameters().getCoseStructureType(),
                    cose.getCoseSignStructure() instanceof COSESign1);

            COSEProtectedHeader bodyProtectedHeader = cose.getBodyProtectedHeader();
            COSEProtectedHeader signerProtectedHeader = cose.getSignerProtectedHeader();

            COSEUnprotectedHeader bodyUnprotectedHeader = cose.getBodyUnprotectedHeader();
            COSEUnprotectedHeader signerUnprotectedHeader = cose.getSignerUnprotectedHeader();

            COSEProtectedHeader protectedHeader = null;
            COSEUnprotectedHeader unprotectedHeader = null;
            if (COSESignatureType.COSE_SIGN == cose.getContext()) {
                assertNotNull(bodyProtectedHeader);
                assertTrue(bodyProtectedHeader.isEmpty());
                assertNotNull(signerProtectedHeader);
                assertFalse(signerProtectedHeader.isEmpty());

                assertNotNull(bodyUnprotectedHeader);
                assertTrue(bodyUnprotectedHeader.isEmpty());
                assertNotNull(signerUnprotectedHeader);
                assertEquals(SignatureLevel.CB_AdES_BASELINE_B == getSignatureParameters().getSignatureLevel(), signerUnprotectedHeader.isEmpty());

                protectedHeader = signerProtectedHeader;
                unprotectedHeader = signerUnprotectedHeader;

            } else if (COSESignatureType.COSE_SIGN1 == cose.getContext()) {
                assertNotNull(bodyProtectedHeader);
                assertFalse(bodyProtectedHeader.isEmpty());
                assertNull(signerProtectedHeader);

                assertNotNull(bodyUnprotectedHeader);
                assertEquals(SignatureLevel.CB_AdES_BASELINE_B == getSignatureParameters().getSignatureLevel(), bodyUnprotectedHeader.isEmpty());
                assertNull(signerUnprotectedHeader);

                protectedHeader = bodyProtectedHeader;
                unprotectedHeader = bodyUnprotectedHeader;

            } else {
                fail(String.format("Unsupported context '%s'!", cose.getContext()));
            }

            List<CBORValue> keySet = protectedHeader.getValue().getKeys();
            assertTrue(Utils.isCollectionNotEmpty(keySet));
            for (CBORValue signedPropertyKey : keySet) {
                assertTrue(CBORUtils.getSupportedProtectedCriticalHeaders().contains(signedPropertyKey));
            }

            CBORValue crit = protectedHeader.getHeader(COSEHeaderParameter.CRIT.cbor());
            if (crit != null) {
                assertTrue(crit.isArray());
                assertInstanceOf(CBORValue.class, crit);

                assertTrue(crit.size() > 0);
                for (CBORValue critItem : crit.getElements()) {
                    assertTrue(critItem.isUnsignedInteger() || critItem.isNegativeInteger());

                    BigInteger labelId = critItem.asInteger();
                    assertNotNull(labelId);

                    assertTrue(CBORUtils.getSupportedProtectedCriticalHeaders().contains(critItem));
                    assertTrue(CBORUtils.isRequiredCriticalHeader(critItem));
                }
            }
        }
    }

    @Override
    protected void checkSignatureValue(DiagnosticData diagnosticData) {
        super.checkSignatureValue(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.getEncryptionAlgorithm() != null && signatureWrapper.getDigestAlgorithm() != null &&
                    signatureWrapper.getEncryptionAlgorithm().isEquivalent(EncryptionAlgorithm.ECDSA)) {
                assertFalse(DSSASN1Utils.isAsn1EncodedSignatureValue(signatureWrapper.getSignatureValue()), "PLAIN-ECDSA is expected!");

                int bitLength = DSSASN1Utils.getSignatureValueBitLength(signatureWrapper.getSignatureValue());
                switch (signatureWrapper.getDigestAlgorithm()) {
                    case SHA256:
                        assertEquals(256, bitLength);
                        break;
                    case SHA384:
                        assertEquals(384, bitLength);
                        break;
                    case SHA512:
                        assertTrue(bitLength == 520 || bitLength == 528);
                        break;
                    default:
                        fail(String.format("DigestAlgorithm '%s' is not supported for JWS with ECDSA!",
                                signatureWrapper.getDigestAlgorithm()));
                }
            }
        }
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeTypeEnum.COSE;
    }

    @Override
    protected boolean isBaselineT() {
        SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
        return SignatureLevel.CB_AdES_BASELINE_LTA.equals(signatureLevel)
                || SignatureLevel.CB_AdES_BASELINE_LT.equals(signatureLevel)
                || SignatureLevel.CB_AdES_BASELINE_T.equals(signatureLevel);
    }


    @Override
    protected boolean isBaselineLTA() {
        SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
        return SignatureLevel.CB_AdES_BASELINE_LTA.equals(signatureLevel);
    }

    @Override
    protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertNotNull(signatureWrapper.getSignatureValue());
        }
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        super.checkStructureValidation(diagnosticData);

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            COSESignatureType coseSignatureType = signature.getCOSESignatureType();
            assertNotNull(coseSignatureType);

            if (signature.isCounterSignature()) {
                assertEquals(COSESignatureType.COSE_COUNTER_SIGNATURE_V2, coseSignatureType);
            } else if (COSEStructureType.COSE_SIGN == getSignatureParameters().getCoseStructureType()) {
                assertEquals(COSESignatureType.COSE_SIGN, coseSignatureType);
            } else if (COSEStructureType.COSE_SIGN1 == getSignatureParameters().getCoseStructureType()) {
                assertEquals(COSESignatureType.COSE_SIGN1, coseSignatureType);
            } else {
                fail("COSE structure type is not defined!");
            }
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertTrue(signatureWrapper.isSigningCertificateIdentified());
            assertTrue(signatureWrapper.isSigningCertificateReferencePresent());

            CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
            assertNotNull(signingCertificateReference);
            assertTrue(signingCertificateReference.isDigestValuePresent());
            assertTrue(signingCertificateReference.isDigestValueMatch());
            if (signingCertificateReference.isIssuerSerialPresent()) {
                assertTrue(signingCertificateReference.isIssuerSerialMatch());
            }

            CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
            assertNotNull(signingCertificate);
            String signingCertificateId = signingCertificate.getId();
            String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
            String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
            assertEquals(signingCertificate.getCertificateDN(), certificateDN);
            assertEquals(signingCertificate.getSerialNumber(), certificateSerialNumber);

            assertTrue(Utils.isCollectionEmpty(signatureWrapper.foundCertificates()
                    .getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

            FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
            List<RelatedCertificateWrapper> signingCertificates = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
            if (getSignatureParameters().isIncludeCertificateChainThumbprints()) {
                BaselineBCertificateSelector certificateSelector = new BaselineBCertificateSelector(
                        getSignatureParameters().getSigningCertificate(), getSignatureParameters().getCertificateChain())
                        .setTrustAnchorBPPolicy(getSignatureParameters().bLevel().isTrustAnchorBPPolicy())
                        .setTrustedCertificateSource(getTrustedCertificateSource());
                assertEquals(certificateSelector.getCertificates().size(), signingCertificates.size());
            } else {
                assertEquals(1, signingCertificates.size());
            }

            List<CertificateRefWrapper> signingCertificateRefs = null;
            for (RelatedCertificateWrapper certificateWrapper : signingCertificates) {
                if (signatureWrapper.getSigningCertificate().getId().equals(certificateWrapper.getId())) {
                    signingCertificateRefs = certificateWrapper.getReferences();
                    break;
                }
            }
            assertNotNull(signingCertificateRefs);

            List<RelatedCertificateWrapper> kidCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER);
            List<RelatedCertificateWrapper> x5uCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.X509_URL);

            int signCertRefs = 1 + (Utils.isCollectionNotEmpty(kidCerts) ? 1 : 0) + (Utils.isCollectionNotEmpty(x5uCerts) ? 1 : 0);
            assertEquals(signCertRefs, signingCertificateRefs.size());

            if (getSignatureParameters().isIncludeKeyIdentifier()) {
                assertEquals(1, kidCerts.size());
            } else if (Utils.isStringNotEmpty(getSignatureParameters().getX509Url())) {
                assertTrue(Utils.isCollectionNotEmpty(x5uCerts));
            } else {
                assertEquals(0, kidCerts.size());
                assertEquals(0, x5uCerts.size());
            }

            for (CertificateRefWrapper certificateRef : signingCertificateRefs) {
                if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getDigestAlgoAndValue());
                    assertNotNull(certificateRef.getDigestMethod());
                    assertTrue(certificateRef.isDigestValuePresent());
                    assertTrue(certificateRef.isDigestValueMatch());
                    assertNull(certificateRef.getIssuerSerial());

                } else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getCertificateId());
                    assertNotNull(certificateRef.getIssuerSerial());
                    assertTrue(certificateRef.isIssuerSerialPresent());
                    assertTrue(certificateRef.isIssuerSerialMatch());
                    assertNull(certificateRef.getDigestAlgoAndValue());
                }
            }
        }
    }

    @Override
    protected void checkReportsSignatureIdentifier(Reports reports) {
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
            SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());

            SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
            assertNotNull(signatureIdentifier);

            assertNotNull(signatureIdentifier.getSignatureValue());
            assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
        }
    }

    @Override
    protected void verifyCertificateSourceData(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
        super.verifyCertificateSourceData(certificateSource, foundCertificates);

        if (certificateSource instanceof CBAdESCertificateSource) {
            CBAdESCertificateSource cbadesCertificateSource = (CBAdESCertificateSource) certificateSource;
            assertEquals(cbadesCertificateSource.getKeyIdentifierCertificates().size(),
                    foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size() +
                            foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
            assertEquals(cbadesCertificateSource.getKeyIdentifierCertificateRefs().size(),
                    foundCertificates.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size() +
                            foundCertificates.getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
        }
    }

    @Override
    protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
        super.checkMessageDigestAlgorithm(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
                if (DigestMatcherType.COSE_SIG_STRUCTURE.equals(digestMatcher.getType()) ||
                        DigestMatcherType.SIG_D_ENTRY.equals(digestMatcher.getType())) {
                    assertNotNull(digestMatcher.getDigestMethod());
                    assertNotNull(digestMatcher.getDigestValue());
                } else if (DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE.equals(digestMatcher.getType())) {
                    assertNull(digestMatcher.getDigestMethod());
                    assertNull(digestMatcher.getDigestValue());
                } else {
                    fail(String.format("Unexpected DigestMatcherType reached : %s", digestMatcher.getType()));
                }
            }
        }
    }

}
