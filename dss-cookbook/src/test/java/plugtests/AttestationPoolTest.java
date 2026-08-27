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
package plugtests;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlAttestation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationDocument;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPresentationInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentValidator;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationPresentation;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.attestation.AttestationDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static java.time.Duration.ofSeconds;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * This test is only to ensure that we don't have exception with valid? attestation files
 */
class AttestationPoolTest extends AbstractTestSignaturePool {

    private static final Logger LOG = LoggerFactory.getLogger(AttestationPoolTest.class);

    private static DSSDocument document;

    private static Stream<Arguments> data() {

        // -Dattestation.pool.folder=...

        String signaturePoolFolder = System.getProperty("attestation.pool.folder", "src/test/resources/attestation-pool");
        File folder = new File(signaturePoolFolder);
        Collection<File> listFiles = Utils.listFiles(folder, new String[] { "json", "jwt", "cbor", "mdoc", "mdl" }, true);
        Collection<Arguments> dataToRun = new ArrayList<>();
        for (File file : listFiles) {
            dataToRun.add(Arguments.of(file));
        }
        return dataToRun.stream();
    }

    @ParameterizedTest(name = "Validation {index} : {0}")
    @MethodSource("data")
    void testValidate(File fileToTest) {
        LOG.info("Begin : {}", fileToTest.getAbsolutePath());
        document = new FileDocument(fileToTest);
        try {
            assertTimeout(ofSeconds(3L), super::validate, "Execution exceeded timeout for file " + fileToTest);
            LOG.info("End : {}", fileToTest.getAbsolutePath());
        } catch (Exception e) {
            fail("Validation of " + fileToTest + " failed", e);
        }
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        DefaultAttestationDocumentValidator validator = DefaultAttestationDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(certificateVerifier());
        validator.setTokenExtractionStrategy(getTokenExtractionStrategy());
        validator.setSignaturePolicyProvider(getSignaturePolicyProvider());
        validator.setTokenIdentifierProvider(getTokenIdentifierProvider());
        validator.setSigningCertificateSource(getSigningCertificateSource());
        validator.setAttestationRevocationSource(null);

        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        signaturePolicyProvider.setDataLoader(null);
        validator.setSignaturePolicyProvider(signaturePolicyProvider);

        return validator;
    }

    @Override
    public void validate() {
        // do nothing
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return document;
    }

    @Override
    protected void checkValidationContext(SignedDocumentValidator validator) {
        super.checkValidationContext(validator);

        AttestationDocumentValidator attestationValidator = assertInstanceOf(AttestationDocumentValidator.class, validator);
        AttestationPresentation attestationPresentation = attestationValidator.getAttestationPresentation();
        assertNotNull(attestationPresentation);
        assertNotNull(attestationPresentation.getDocumentFormat());

        List<Attestation> attestations = attestationPresentation.getAttestations();
        assertEquals(1, Utils.collectionSize(attestations));

        Attestation attestation = attestations.get(0);
        assertNotNull(attestation.getId());
        assertNotNull(attestation.getDSSId());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        // skip
    }

    @Override
    protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
        super.verifyDiagnosticData(diagnosticData);

        checkAttestationPresentationInfo(diagnosticData);
        checkAttestations(diagnosticData);
        checkEAAStatusTokens(diagnosticData);
    }

    protected void checkAttestationPresentationInfo(DiagnosticData diagnosticData) {
        XmlAttestationPresentationInfo attestationPresentationInfo = diagnosticData.getAttestationPresentationInfo();
        assertNotNull(attestationPresentationInfo);
        assertNotNull(attestationPresentationInfo.getFormat());
        assertEquals(attestationPresentationInfo.getFormat(), diagnosticData.getAttestationPresentationFormat());
        List<XmlAttestationDocument> documents = attestationPresentationInfo.getDocuments();
        assertTrue(Utils.isCollectionNotEmpty(documents));
        assertEquals(documents.size(), diagnosticData.getAttestations().size());
    }

    protected void checkAttestations(DiagnosticData diagnosticData) {
        List<AttestationWrapper> attestations = diagnosticData.getAttestations();
        assertEquals(1, attestations.size());

        AttestationWrapper attestationWrappper = attestations.get(0);
        assertNotNull(attestationWrappper.getId());

        checkAttestationDigestMatchers(diagnosticData);
        checkClaims(diagnosticData);
        checkAttestationRevocations(diagnosticData);
    }

    protected void checkAttestationRevocations(DiagnosticData diagnosticData) {
        for (AttestationWrapper attestation : diagnosticData.getAllAttestations()) {
            for (AttestationRevocationWrapper attestationRevocationWrapper : attestation.getAttestationRevocations()) {
                assertNotNull(attestationRevocationWrapper.getId());
                assertNotNull(attestationRevocationWrapper.getStatus());
            }
        }
    }

    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        for (AttestationWrapper attestation : diagnosticData.getAttestations()) {
            for (XmlDigestMatcher digestMatcher : attestation.getDigestMatchers()) {
                if (AttestationProfile.ISO_IEC_MDOC == attestation.getAttestationProfile()) {
                    assertNotNull(digestMatcher.getDisclosableClaim().getId());
                    assertNotNull(digestMatcher.getDisclosableClaim().getNamespace());
                }
            }
        }
    }

    protected void checkClaims(DiagnosticData diagnosticData) {
        for (AttestationWrapper attestation : diagnosticData.getAttestations()) {
            List<ClaimWrapper> attestationPayloadClaims = new ArrayList<>(attestation.getAllAttestationPayloadClaims());
            assertTrue(Utils.isCollectionNotEmpty(attestationPayloadClaims));
            assertTrue(Utils.isCollectionNotEmpty(attestation.getAllAttestationPayloadClaimNames()));
            checkClaimsRecursively(attestationPayloadClaims, true);
            for (ClaimWrapper claimWrapper : attestationPayloadClaims) {
                ClaimWrapper claimByHeaderName = attestation.getClaimByHeaderName(claimWrapper.getName());
                assertNotNull(claimByHeaderName);
                assertEquals(claimByHeaderName.getName(), claimWrapper.getName());
                assertEquals(claimByHeaderName.getNamespace(), claimWrapper.getNamespace());
                assertEquals(claimByHeaderName.getText(), claimWrapper.getText());
                assertEquals(claimByHeaderName.getNumber(), claimWrapper.getNumber());
                assertEquals(claimByHeaderName.getBoolean(), claimWrapper.getBoolean());
                assertArrayEquals(claimByHeaderName.getBinary(), claimWrapper.getBinary());
                if (claimWrapper.getDateTime() != null) {
                    assertNotNull(claimByHeaderName.getDateTime());
                    assertEquals(0, claimWrapper.getDateTime().compareTo(claimByHeaderName.getDateTime()));
                } else {
                    assertNull(claimByHeaderName.getDateTime());
                }
                if (claimWrapper.getList() != null) {
                    assertEquals(claimWrapper.getList().size(), claimByHeaderName.getList().size());
                } else {
                    assertNull(claimByHeaderName.getList());
                }
                if (claimWrapper.getMap() != null) {
                    assertNotNull(claimByHeaderName.getMap());
                    assertEquals(claimWrapper.getMap(), claimByHeaderName.getMap());
                } else {
                    assertNull(claimByHeaderName.getMap());
                }

                if (AttestationProfile.ISO_IEC_MDOC == attestation.getAttestationProfile() && claimWrapper.isSelectivelyDisclosable()) {
                    assertNotNull(claimWrapper.getNamespace());
                }
            }
        }
    }

    protected void checkClaimsRecursively(Collection<ClaimWrapper> claims, boolean mapOrigin) {
        for (ClaimWrapper claimWrapper : claims) {
            assertEquals(claimWrapper.getName() != null, mapOrigin);

            assertTrue(claimWrapper.getText() != null || claimWrapper.getDateTime() != null ||
                    claimWrapper.getNumber() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getText() != null, claimWrapper.getDateTime() != null ||
                    claimWrapper.getNumber() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getDateTime() != null, claimWrapper.getText() != null ||
                    claimWrapper.getNumber() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getNumber() != null, claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(Utils.isCollectionNotEmpty(claimWrapper.getList()), claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || claimWrapper.getNumber() != null ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getBoolean() != null, claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getNumber() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getBinary() != null, claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getNumber() != null || claimWrapper.getBoolean() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getMap() != null, claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getNumber() != null || claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isNull(), claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getNumber() != null || claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null);

            assertTrue(claimWrapper.isText() || claimWrapper.isDateTime() ||
                    claimWrapper.isNumber() || claimWrapper.isList() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isText(), claimWrapper.isDateTime() ||
                    claimWrapper.isNumber() || claimWrapper.isList() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isDateTime(), claimWrapper.isText() ||
                    claimWrapper.isNumber() || claimWrapper.isList() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isNumber(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isList(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isNumber() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isBoolean(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isNumber() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isBinary(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isNumber() || claimWrapper.isBoolean() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isMap(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isNumber() || claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isNull(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isNumber() || claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap());

            if ((!claimWrapper.isBinary() || Utils.isArrayNotEmpty(claimWrapper.getBinary())) &&
                    (!claimWrapper.isText() || Utils.isStringNotEmpty(claimWrapper.getText()))) {
                assertTrue(Utils.isStringNotEmpty(claimWrapper.getDisplayValue()));
            }

            if (claimWrapper.getList() != null) {
                checkClaimsRecursively(claimWrapper.getList(), false);
            } else if (claimWrapper.getMap() != null) {
                checkClaimsRecursively(claimWrapper.getMap().values(), true);
            }
        }
    }

    protected void checkEAAStatusTokens(DiagnosticData diagnosticData) {
        for (AttestationRevocationTokenWrapper attestationRevocationTokenWrapper : diagnosticData.getAllAttestationRevocationTokens()) {
            assertNotNull(attestationRevocationTokenWrapper.getId());
            assertNotNull(attestationRevocationTokenWrapper.getType());
            assertNotNull(attestationRevocationTokenWrapper.getOrigin());
            assertNotNull(attestationRevocationTokenWrapper.getIssuedAt());
            assertNotNull(attestationRevocationTokenWrapper.getExpirationTime());

            assertNotNull(attestationRevocationTokenWrapper.foundCertificates());
            assertNotNull(attestationRevocationTokenWrapper.foundCertificates().getRelatedCertificates());
            assertNotNull(attestationRevocationTokenWrapper.foundCertificates().getOrphanCertificates());

            if (attestationRevocationTokenWrapper.getSigningCertificate() != null) {
                assertTrue(Utils.isCollectionNotEmpty(attestationRevocationTokenWrapper.getCertificateChain()));
            }
        }
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        for (AttestationWrapper attestation : diagnosticData.getAttestations()) {
            for (SignatureWrapper signatureWrapper : attestation.getAttestationSignatures()) {
                if (signatureWrapper.isSignatureValid()) {
                    assertEquals(1, Utils.collectionSize(signatureWrapper.getSignatureScopes()));
                    XmlSignatureScope signatureScope = signatureWrapper.getSignatureScopes().get(0);
                    assertNotNull(signatureScope.getScope());
                    assertNotNull(signatureScope.getSignerData());
                    assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue());
                    assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod());
                    assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue());
                    assertEquals(SignatureScopeType.ATTESTATION_SIGNATURE, signatureScope.getScope());
                }
            }
            SignatureWrapper keyBindingSignature = attestation.getKeyBindingSignature();
            if (keyBindingSignature != null && keyBindingSignature.isSignatureValid()) {
                assertEquals(1, Utils.collectionSize(keyBindingSignature.getSignatureScopes()));
                XmlSignatureScope signatureScope = keyBindingSignature.getSignatureScopes().get(0);
                assertNotNull(signatureScope.getScope());
                assertNotNull(signatureScope.getSignerData());
                assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue());
                assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod());
                assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue());
                assertEquals(SignatureScopeType.KEY_BINDING_SIGNATURE, signatureScope.getScope());
            }
        }
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
        // may include orphan certificate references (e.g. x5u)
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifyDetailedReport(DetailedReport detailedReport) {
        assertNotNull(detailedReport);

        int nbBBBs = detailedReport.getBasicBuildingBlocksNumber();
        for (int i = 0; i < nbBBBs; i++) {
            String id = detailedReport.getBasicBuildingBlocksSignatureId(i);
            assertNotNull(id);

            Indication indication = detailedReport.getBasicBuildingBlocksIndication(id);
            assertNotNull(indication);
            if (!Indication.PASSED.equals(indication)) {
                SubIndication subIndication = detailedReport.getBasicBuildingBlocksSubIndication(id);
                assertNotNull(subIndication);
            }
        }

        List<String> attestationIds = detailedReport.getAttestationIds();
        for (String attestationId : attestationIds) {
            XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(attestationId);
            assertNotNull(xmlAttestation);

            Indication indication = detailedReport.getAttestationValidationIndication(attestationId);
            assertNotNull(indication);
            if (!Indication.PASSED.equals(indication)) {
                SubIndication subIndication = detailedReport.getAttestationValidationSubIndication(attestationId);
                assertNotNull(subIndication);
            }
        }
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        assertNotNull(simpleReport);

        List<String> attestationPresentationIdList = simpleReport.getAttestationIdList();
        assertEquals(1, attestationPresentationIdList.size());

        assertEquals(attestationPresentationIdList.get(0), simpleReport.getFirstAttestationId());

        String attestationPresentationId = simpleReport.getFirstAttestationId();

        Indication indication = simpleReport.getIndication(attestationPresentationId);
        assertNotNull(indication);
        assertTrue(Indication.PASSED.equals(indication) || Indication.INDETERMINATE.equals(indication)
                || Indication.FAILED.equals(indication));
        if (Indication.PASSED.equals(indication)) {

            assertNull(simpleReport.getSubIndication(attestationPresentationId));
            assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(attestationPresentationId)));

        } else {
            SubIndication subIndication = simpleReport.getSubIndication(attestationPresentationId);
            assertNotNull(subIndication);
            assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(attestationPresentationId)));
        }
        assertNotNull(simpleReport.getAttestationQualification(attestationPresentationId));

        List<XmlSignature> attestationSignatures = simpleReport.getAttestationSignatures(attestationPresentationId);
        for (XmlSignature xmlSignature : attestationSignatures) {
            verifySimpleReportSignature(simpleReport, xmlSignature);
        }

        XmlSignature keyBindingSignature = simpleReport.getAttestationKeyBindingSignature(attestationPresentationId);
        if (keyBindingSignature != null) {
            verifySimpleReportSignature(simpleReport, keyBindingSignature);
        }
    }

    private void verifySimpleReportSignature(SimpleReport simpleReport, XmlSignature xmlSignature) {
        String sigId = xmlSignature.getId();

        Indication indication = simpleReport.getIndication(sigId);
        assertNotNull(indication);
        assertTrue(Indication.TOTAL_PASSED.equals(indication) || Indication.INDETERMINATE.equals(indication)
                || Indication.TOTAL_FAILED.equals(indication));
        if (Indication.TOTAL_PASSED.equals(indication)) {
            assertTrue(Utils.isCollectionNotEmpty(simpleReport.getSignatureScopes(sigId)));

            assertNull(simpleReport.getSubIndication(sigId));
            assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(sigId)));

            if (!createdWithTrustAnchor(simpleReport.getCertificateChain(sigId))
                    && !timestampedWithTrustAnchor(simpleReport.getSignatureTimestamps(sigId))
                    && !preservedByERWithTrustAnchor(simpleReport.getSignatureEvidenceRecords(sigId))
                    && Utils.isStringNotEmpty(simpleReport.getSignedBy(sigId))) {
                assertNotNull(simpleReport.getExtensionPeriodMax(sigId));
            }

        } else {
            SubIndication subIndication = simpleReport.getSubIndication(sigId);
            assertNotNull(subIndication);
            assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(sigId)));
        }
        assertNotNull(simpleReport.getSignatureQualification(sigId));

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(sigId);
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : signatureTimestamps) {
            String tstId = xmlTimestamp.getId();
            assertNotNull(tstId);

            Indication timestampIndication = simpleReport.getIndication(tstId);
            assertNotNull(timestampIndication);
            assertTrue(Indication.PASSED.equals(timestampIndication) || Indication.INDETERMINATE.equals(timestampIndication)
                    || Indication.FAILED.equals(timestampIndication));
            if (timestampIndication != Indication.PASSED) {
                assertNotNull(simpleReport.getSubIndication(tstId));
                assertTrue(Utils.isCollectionNotEmpty(simpleReport.getAdESValidationErrors(tstId)));
            }
            assertNotNull(simpleReport.getTimestampQualification(tstId));
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

}