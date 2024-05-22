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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.BaselineRequirementsChecker;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureUtils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.XAdESNamespace;
import eu.europa.esig.xades.definition.XAdESPath;
import eu.europa.esig.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.xmldsig.definition.XMLDSigAttribute;
import eu.europa.esig.xmldsig.definition.XMLDSigPath;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.List;

/**
 * Performs checks according to EN 319 132-1 v1.1.1
 * "6.3 Requirements on XAdES signature's elements, qualifying properties and services"
 *
 */
public class XAdESBaselineRequirementsChecker extends BaselineRequirementsChecker<XAdESSignature> {

    private static final Logger LOG = LoggerFactory.getLogger(XAdESBaselineRequirementsChecker.class);

    /**
     * Default constructor
     *
     * @param signature {@link XAdESSignature}
     * @param offlineCertificateVerifier {@link CertificateVerifier}
     */
    public XAdESBaselineRequirementsChecker(final XAdESSignature signature,
                                            final CertificateVerifier offlineCertificateVerifier) {
        super(signature, offlineCertificateVerifier);
    }

    @Override
    public boolean hasBaselineBProfile() {
        Element signatureElement = signature.getSignatureElement();
        XAdESPath xadesPaths = signature.getXAdESPaths();
        // ds:KeyInfo (Cardinality == 1)
        if (getNumberOfOccurrences(signatureElement, XMLDSigPath.KEY_INFO_PATH) != 1) {
            LOG.warn("ds:KeyInfo element shall be present for XAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // ds:SignedInfo/ds:CanonicalizationMethod (Cardinality == 1)
        if (getNumberOfOccurrences(signatureElement, XMLDSigPath.SIGNED_INFO_CANONICALIZATION_METHOD) != 1) {
            LOG.warn("ds:SignedInfo/ds:CanonicalizationMethod element shall be present for XAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // ds:SignedInfo/ds:Reference (Cardinality >= 2)
        if (getNumberOfOccurrences(signatureElement, XMLDSigPath.SIGNED_INFO_REFERENCE_PATH) < 2) {
            LOG.warn("ds:SignedInfo/ds:Reference element shall be present for XAdES-BASELINE-B signature (cardinality >= 2)!");
            return false;
        }
        // ds:SignedInfo/ds:Reference/ds:Transforms (Cardinality 0 or 1)
        NodeList referenceList = DomUtils.getNodeList(signatureElement, XMLDSigPath.SIGNED_INFO_REFERENCE_PATH);
        if (referenceList != null && referenceList.getLength() > 0) {
            for (int ii = 0; ii < referenceList.getLength(); ii++) {
                Element reference = (Element) referenceList.item(ii);
                if (DomUtils.getNodesAmount(reference, XMLDSigPath.TRANSFORMS_PATH) > 1) {
                    LOG.warn("Only one ds:Reference/ds:Transforms may be present for XAdES-BASELINE-B signature (cardinality 0 or 1)!");
                    return false;
                }
            }
        }
        // SigningTime (Cardinality == 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSigningTimePath()) != 1) {
            LOG.warn("SigningTime shall be present for XAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // SigningCertificate/SigningCertificateV2 (Cardinality == 1)
        if (!isSigningCertificatePresent(signatureElement, xadesPaths)) {
            LOG.warn("SigningCertificate(V2) shall be present for XAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // DataObjectFormat (Cardinality >= 0)
        NodeList dataObjectFormatList = getDataObjectFormatList(signatureElement, xadesPaths);
        for (int ii = 0; ii < dataObjectFormatList.getLength(); ii++) {
            Element dataObjectFormat = (Element) dataObjectFormatList.item(ii);
            if (!isValidXAdESBaselineDataObjectFormat(dataObjectFormat, signature, xadesPaths)) {
                return false;
            }
        }
        // SignerRole/SignerRoleV2 (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSignerRolePath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getSignerRoleV2Path()) > 1) {
            LOG.warn("Only one SignerRole(V2) may be present for XAdES-BASELINE-B signature (cardinality 0 or 1)!");
            return false;
        }
        // CommitmentTypeIndication  (Cardinality >= 0)
        // SignatureProductionPlace/SignatureProductionPlaceV2 (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSignatureProductionPlacePath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getSignatureProductionPlaceV2Path()) > 1) {
            LOG.warn("Only one SignatureProductionPlace(V2) may be present for XAdES-BASELINE-B signature (cardinality 0 or 1)!");
            return false;
        }
        // CounterSignature (Cardinality >= 0)
        // AllDataObjectsTimeStamp (Cardinality >= 0)
        // SignaturePolicyIdentifier (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSignaturePolicyIdentifierPath()) > 1) {
            LOG.warn("Only one SignaturePolicyIdentifier may be present for XAdES-BASELINE-B signature (cardinality 0 or 1)!");
            return false;
        }
        // SignaturePolicyStore (Cardinality 0 or 1, conditioned presence requirement (m))
        int signaturePolicyStoreAmount = getNumberOfOccurrences(signatureElement, xadesPaths.getSignaturePolicyStorePath());
        if (signaturePolicyStoreAmount == 1) {
            if (!isSignaturePolicyIdentifierHashPresent()) {
                LOG.warn("SignaturePolicyStore shall not be present for XAdES-BASELINE-B signature with not defined " +
                        "SignaturePolicyIdentifier/SigPolicyHash (requirement (m))!");
            }
        } else if (signaturePolicyStoreAmount > 1) {
            LOG.warn("Only one SignaturePolicyIdentifier may be present for XAdES-BASELINE-B signature (cardinality 0 or 1)!");
            return false;
        }
        // ArchiveTimeStamp (defined in namespace whose URI is "http://uri.etsi.org/01903/v1.3.2#") (Cardinality == 0)
        String archiveTimestampPath = xadesPaths.getArchiveTimestampPath();
        if (Utils.isStringNotEmpty(archiveTimestampPath)) {
            NodeList archiveTimeStampList = DomUtils.getNodeList(signatureElement, archiveTimestampPath);
            for (int ii = 0; ii < archiveTimeStampList.getLength(); ii++) {
                Node archiveTimeStamp = archiveTimeStampList.item(ii);
                if (XAdESNamespace.XADES_132.getUri().equals(archiveTimeStamp.getNamespaceURI())) {
                    LOG.warn("xades132:ArchiveTimeStamp shall not be present for XAdES-BASELINE-B signature (cardinality == 0)!");
                    return false;
                }
            }
        }
        // Additional requirement (a)
        if (!containsSigningCertificate(signature.getCertificateSource().getKeyInfoCertificates())) {
            LOG.warn("Signing certificate shall be present in ds:KeyInfo/ds:X509Data/ds:X509Certificate " +
                    "for XAdES-BASELINE-B signature (requirement (a))!");
            return false;
        }
        // Additional requirement (d)
        final Element signedInfo = signature.getSignedInfo();
        if (signedInfo != null) {
            String canonicalizationMethod = DomUtils.getValue(signedInfo, XMLDSigPath.CANONICALIZATION_ALGORITHM_PATH);
            if (Utils.isStringNotEmpty(canonicalizationMethod)) {
                switch (canonicalizationMethod) {
                    case Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS:
                    case Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS:
                    case Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS:
                    case Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS:
                    case Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS:
                    case Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS:
                        break;
                    default:
                        LOG.warn("ds:SignedInfo/ds:CanonicalizationMethod contains not accepted Algorithm attribute value " +
                                "for XAdES-BASELINE-B signature (requirement (d))!");
                        return false;
                }
            }
        }
        // Additional requirement (i)
        String signingCertificateV2Path = xadesPaths.getSigningCertificateV2Path();
        if (Utils.isStringNotEmpty(signingCertificateV2Path)) {
            NodeList signingCertificateV2List = DomUtils.getNodeList(signatureElement, signingCertificateV2Path);
            if (signingCertificateV2List.getLength() == 1) {
                Node signingCertificateV2 = signingCertificateV2List.item(0);
                NodeList certList = DomUtils.getNodeList(signingCertificateV2, xadesPaths.getCurrentCertChildren());
                for (int ii = 0; ii < certList.getLength(); ii++) {
                    Element cert = (Element) certList.item(ii);
                    if (cert.hasAttribute(XAdES132Attribute.URI.getAttributeName())) {
                        LOG.warn("SigningCertificateV2/Cert shall not include URI optional attribute " +
                                "for XAdES-BASELINE-B signature (requirement (i))!");
                        return false;
                    }
                }
            }
        }
        // Additional requirement (k)
        List<Reference> references = signature.getReferences();
        for (Reference reference : references) {
            if ((DomUtils.startsFromHash(reference.getURI()) || DomUtils.isXPointerQuery(reference.getURI())) &&
                    (DSSXMLUtils.isSignedProperties(reference, xadesPaths) ||
                    DSSXMLUtils.isCounterSignatureReferenceType(reference.getType()) ||
                    DSSXMLUtils.isManifestReferenceType(reference.getType()) ||
                    DSSXMLUtils.isKeyInfoReference(reference, signatureElement) ||
                    DSSXMLUtils.isSignaturePropertiesReference(reference, signatureElement))) {
                continue;
            }
            String referenceId = reference.getId();
            if (Utils.isStringNotEmpty(referenceId)) {
                boolean correspondingDataObjectFormatFound = false;
                for (int ii = 0; ii < dataObjectFormatList.getLength(); ii++) {
                    Element dataObjectFormat = (Element) dataObjectFormatList.item(ii);
                    String objectReference = dataObjectFormat.getAttribute(XAdES132Attribute.OBJECT_REFERENCE.getAttributeName());
                    if (referenceId.equals(DomUtils.getId(objectReference))) {
                        correspondingDataObjectFormatFound = true;
                    }
                }
                if (!correspondingDataObjectFormatFound) {
                    LOG.warn("DataObjectFormat shall be generated for each signed data " +
                            "for XAdES-BASELINE-B signature (requirement (k))!");
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public boolean hasBaselineTProfile() {
        if (!minimalTRequirement()) {
            return false;
        }
        Element signatureElement = signature.getSignatureElement();
        XAdESPath xadesPaths = signature.getXAdESPaths();

        // Additional requirement (n)
        NodeList signatureTimeStampList = DomUtils.getNodeList(signatureElement, xadesPaths.getSignatureTimestampPath());
        for (int ii = 0; ii < signatureTimeStampList.getLength(); ii++) {
            Node signatureTimeStamp = signatureTimeStampList.item(ii);
            NodeList encapsulatedTimestampList = DomUtils.getNodeList(signatureTimeStamp, xadesPaths.getCurrentEncapsulatedTimestamp());
            if (encapsulatedTimestampList.getLength() != 1) {
                LOG.warn("SignatureTimeStamp shall contain only one electronic timestamp for XAdES-BASELINE-T signature (requirement (n))!");
                return false;
            }
        }
        // Additional requirement (o)
        if (!signatureTimestampsCreatedBeforeSignCertExpiration()) {
            LOG.warn("SignatureTimeStamp shall be created before expiration of the signing-certificate " +
                    "for XAdES-BASELINE-T signature (requirement (o))!");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineLTProfile() {
        if (!minimalLTRequirement()) {
            return false;
        }
        Element signatureElement = signature.getSignatureElement();
        XAdESPath xadesPaths = signature.getXAdESPaths();
        // CertificateValues (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getCertificateValuesPath()) > 1) {
            LOG.warn("Only one CertificateValues element may be present for XAdES-BASELINE-LT signature (cardinality 0 or 1)!");
            return false;
        }
        // CompleteCertificateRefs/CompleteCertificateRefsV2 (Cardinality == 0)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getCompleteCertificateRefsPath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getCompleteCertificateRefsV2Path()) > 0) {
            LOG.warn("CompleteCertificateRefs(V2) shall not be present for XAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // AttrAuthoritiesCertValues (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getAttrAuthoritiesCertValuesPath()) > 1) {
            LOG.warn("Only one AttrAuthoritiesCertValues element may be present for XAdES-BASELINE-LT signature (cardinality 0 or 1)!");
            return false;
        }
        // RevocationValues (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getRevocationValuesPath()) > 1) {
            LOG.warn("Only one RevocationValues element may be present for XAdES-BASELINE-LT signature (cardinality 0 or 1)!");
            return false;
        }
        // CompleteRevocationRefs (Cardinality == 0)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getCompleteRevocationRefsPath()) > 0) {
            LOG.warn("CompleteRevocationRefs shall not be present for XAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // AttributeRevocationValues (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getAttributeRevocationValuesPath()) > 1) {
            LOG.warn("AttributeRevocationValues shall not be present for XAdES-BASELINE-LT signature (cardinality 0 or 1)!");
            return false;
        }
        // SigAndRefsTimeStamp/SigAndRefsTimeStampV2 (Cardinality == 0)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSigAndRefsTimestampPath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getSigAndRefsTimestampV2Path()) > 0) {
            LOG.warn("SigAndRefsTimeStamp(V2) shall not be present for XAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // RefsOnlyTimeStamp/RefsOnlyTimeStampV2 (Cardinality == 0)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getRefsOnlyTimestampPath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getRefsOnlyTimestampV2Path()) > 0) {
            LOG.warn("RefsOnlyTimeStampV2 shall not be present for XAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        return true;
    }

    @Override
    protected boolean containsLTLevelCertificates() {
        Element signatureElement = signature.getSignatureElement();
        XAdESPath xadesPaths = signature.getXAdESPaths();
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getCertificateValuesPath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getAttrAuthoritiesCertValuesPath()) == 0) {
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineLTAProfile() {
        return minimalLTARequirement();
    }

    @Override
    public boolean hasExtendedBESProfile() {
        Element signatureElement = signature.getSignatureElement();
        XAdESPath xadesPaths = signature.getXAdESPaths();
        // SigningTime (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSigningTimePath()) > 1) {
            LOG.warn("Only one SigningTime may be present for XAdES-BES signature (cardinality 0 or 1)!");
            return false;
        }
        // SigningCertificate/SigningCertificateV2 (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSigningCertificatePath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getSigningCertificateV2Path()) > 1) {
            LOG.warn("Only one SigningCertificate(V2) may be present for XAdES-BES signature (cardinality 0 or 1)!");
            return false;
        }
        // CommitmentTypeIndication (Cardinality >= 0)
        // DataObjectFormat (Cardinality >= 0)
        NodeList dataObjectFormatList = getDataObjectFormatList(signatureElement, xadesPaths);
        for (int ii = 0; ii < dataObjectFormatList.getLength(); ii++) {
            Element dataObjectFormat = (Element) dataObjectFormatList.item(ii);
            if (!isValidXAdESDataObjectFormat(dataObjectFormat, signature, xadesPaths)) {
                return false;
            }
        }
        // SignatureProductionPlace/SignatureProductionPlaceV2 (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSignatureProductionPlacePath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getSignatureProductionPlaceV2Path()) > 1) {
            LOG.warn("Only one SignatureProductionPlace(V2) may be present for XAdES-BES signature (cardinality 0 or 1)!");
            return false;
        }
        // SignerRole/SignerRoleV2 (Cardinality 0 or 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSignerRolePath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getSignerRoleV2Path()) > 1) {
            LOG.warn("Only one SignerRole(V2) may be present for XAdES-BES signature (cardinality 0 or 1)!");
            return false;
        }
        // CounterSignature (Cardinality >= 0)
        // AllDataObjectsTimeStamp (Cardinality >= 0)
        // IndividualDataObjectsTimeStamp (Cardinality >= 0)
        // Additional requirement (a)
        if (!isSigningCertificatePresent(signatureElement, xadesPaths) && !isSigningCertificateSignedInKeyInfo()) {
            LOG.warn("SigningCertificate(V2) shall be present for XAdES-BES signature or be present in ds:KeyInfo " +
                    "and signed by the signature (requirement (a))!");
            return false;
        }

        return true;
    }

    @Override
    public boolean hasExtendedEPESProfile() {
        Element signatureElement = signature.getSignatureElement();
        XAdESPath xadesPaths = signature.getXAdESPaths();
        // SignaturePolicyIdentifier (Cardinality == 1)
        if (getNumberOfOccurrences(signatureElement, xadesPaths.getSignaturePolicyIdentifierPath()) != 1) {
            LOG.debug("SignaturePolicyIdentifier shall be present for XAdES-EPES signature (cardinality == 1)!");
            return false;
        }
        // SignaturePolicyStore (Cardinality == 0)
        int signaturePolicyStoreOccurrences = getNumberOfOccurrences(signatureElement, xadesPaths.getSignaturePolicyStorePath());
        if (signaturePolicyStoreOccurrences > 1) {
            LOG.debug("Only one SignaturePolicyStore may be present for XAdES-EPES signature (cardinality 0 or 1)!");
            return false;
        }
        // Additional requirement (c)
        if (signaturePolicyStoreOccurrences == 1 && !isSignaturePolicyIdentifierHashPresent()) {
            LOG.debug("SignaturePolicyStore may be present for XAdES-EPES signature only if SignaturePolicyIdentifier is present and " +
                    "it contains SigPolicyHash element (requirement (c))!");
            return false;
        }

        return true;
    }

    @Override
    public boolean hasExtendedTProfile() {
        if (!minimalTRequirement()) {
            return false;
        }
        Element signatureElement = signature.getSignatureElement();
        XAdESPath xadesPaths = signature.getXAdESPaths();

        // Additional requirement (d)
        NodeList signatureTimeStampList = DomUtils.getNodeList(signatureElement, xadesPaths.getSignatureTimestampPath());
        for (int ii = 0; ii < signatureTimeStampList.getLength(); ii++) {
            Node signatureTimeStamp = signatureTimeStampList.item(ii);
            NodeList encapsulatedTimestampList = DomUtils.getNodeList(signatureTimeStamp, xadesPaths.getCurrentEncapsulatedTimestamp());
            if (encapsulatedTimestampList.getLength() == 0) {
                LOG.warn("SignatureTimeStamp shall contain one or more electronic timestamp for XAdES-T signature (requirement (d))!");
                return false;
            }
        }
        // Additional requirement (e)
        if (!signatureTimestampsCreatedBeforeSignCertExpiration()) {
            LOG.warn("SignatureTimeStamp shall be created before expiration of the signing-certificate " +
                    "for XAdES-T signature (requirement (e))!");
            return false;
        }

        return true;
    }

    @Override
    public boolean hasExtendedCProfile() {
        ListCertificateSource certificateSources = getCertificateSourcesExceptLastArchiveTimestamp();
        boolean certificateFound = certificateSources.getNumberOfCertificates() > 0;
        boolean allSelfSigned = certificateFound && certificateSources.isAllSelfSigned();

        Element signatureElement = signature.getSignatureElement();
        XAdESPath xadesPaths = signature.getXAdESPaths();

        // CompleteCertificateRefs/CompleteCertificateRefsV2 (Cardinality == 1)
        int completeCertificateRefsNumberOfOccurrences = getNumberOfOccurrences(signatureElement, xadesPaths.getCompleteCertificateRefsPath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getCompleteCertificateRefsV2Path());
        if (completeCertificateRefsNumberOfOccurrences > 1 || (!allSelfSigned && completeCertificateRefsNumberOfOccurrences == 0)) {
            LOG.debug("CompleteCertificateRefs(V2) shall be present for XAdES-C signature (cardinality == 1)!");
            return false;
        }
        // CompleteRevocationRefs (Cardinality == 1)
        int completeRevocationRefsNumberOfOccurrences = getNumberOfOccurrences(signatureElement, xadesPaths.getCompleteRevocationRefsPath());
        if (completeRevocationRefsNumberOfOccurrences > 1 || (!allSelfSigned && completeRevocationRefsNumberOfOccurrences == 0)) {
            LOG.debug("CompleteRevocationRefs shall be present for XAdES-C signature (cardinality == 1)!");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasExtendedXProfile() {
        Element signatureElement = signature.getSignatureElement();
        XAdESPath xadesPaths = signature.getXAdESPaths();

        final boolean refsOnlyTst = isElementPresent(signatureElement, xadesPaths.getRefsOnlyTimestampPath());
        final boolean refsOnlyTstV2 = isElementPresent(signatureElement, xadesPaths.getRefsOnlyTimestampV2Path());
        final boolean sigAndRefsTst = isElementPresent(signatureElement, xadesPaths.getSigAndRefsTimestampPath());
        final boolean sigAndRefsTstV2 = isElementPresent(signatureElement, xadesPaths.getSigAndRefsTimestampV2Path());
        if (!refsOnlyTst && !refsOnlyTstV2 && !sigAndRefsTst && !sigAndRefsTstV2) {
            LOG.debug("Either RefsOnlyTimestamp(V2) or SigAndRefsTimestamp(V2) shall be present for XAdES-X signature)!");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasExtendedXLProfile() {
        return minimalLTRequirement();
    }

    @Override
    public boolean hasExtendedAProfile() {
        return minimalLTARequirement();
    }

    private boolean isSigningCertificatePresent(Element signatureElement, XAdESPath xadesPaths) {
        return getNumberOfOccurrences(signatureElement, xadesPaths.getSigningCertificatePath()) +
                getNumberOfOccurrences(signatureElement, xadesPaths.getSigningCertificateV2Path()) == 1;
    }

    private NodeList getDataObjectFormatList(Element signatureElement, XAdESPath xadesPaths) {
        return DomUtils.getNodeList(signatureElement, xadesPaths.getDataObjectFormat());
    }

    private boolean isValidXAdESDataObjectFormat(Element dataObjectFormat, XAdESSignature signature, XAdESPath xadesPaths) {
        // 5.2.4 The DataObjectFormat qualifying property
        Element signatureElement = signature.getSignatureElement();
        // This qualifying property shall contain at least one of the following elements: Description, ObjectIdentifier and MimeType.
        if (getNumberOfOccurrences(dataObjectFormat, xadesPaths.getCurrentDescription()) != 1 &&
                getNumberOfOccurrences(dataObjectFormat, xadesPaths.getCurrentObjectIdentifier()) != 1 &&
                getNumberOfOccurrences(dataObjectFormat, xadesPaths.getCurrentMimeType()) != 1) {
            LOG.warn("At least one of the following elements: Description, ObjectIdentifier and MimeType " +
                    "shall be present within DataObjectFormat element for XAdES signature!");
            return false;
        }
        /*
         * The ObjectReference attribute shall reference the ds:Reference child of the ds:SignedInfo or a signed
         * ds:Manifest element referencing the signed data object qualified by this qualifying property.
         */
        String objectReference = dataObjectFormat.getAttribute(XAdES132Attribute.OBJECT_REFERENCE.getAttributeName());
        if (Utils.isStringEmpty(objectReference)) {
            LOG.warn("DataObjectFormat's ObjectReference attribute shall be present for XAdES signature (cardinality == 1)!");
            return false;
        }
        if (!DomUtils.isElementReference(objectReference)) {
            LOG.warn("DataObjectFormat's ObjectReference attribute shall refer to an element within the document!");
            return false;
        }
        String id = DomUtils.getId(objectReference);
        Reference matchingReference = getMatchingReference(id, signature.getReferences(), signatureElement);
        if (matchingReference == null) {
            LOG.warn("DataObjectFormat's ObjectReference attribute shall refer to a signed data object within the document!");
            return false;
        }
        /*
         * If the DataObjectFormat qualifying property references a ds:Reference that in turn references a ds:Object
         * within the XAdES signature, and if this ds:Object element has the MimeType or (and) the Encoding attribute(s),
         * then DataObjectFormat's children MimeType and Encoding shall have exactly the same values, if they are
         * present.
         */
        if (!isDataObjectFormatValuesCompliant(dataObjectFormat, matchingReference, signatureElement, xadesPaths)) {
            return false;
        }
        return true;
    }

    private Reference getMatchingReference(String id, List<Reference> references, Element signatureElement) {
        for (Reference reference : references) {
            if (id.equals(reference.getId())) {
                return reference;
            }
            if (reference.getURI() != null) {
                Element manifestElement = DSSXMLUtils.getManifestById(signatureElement, DomUtils.getId(reference.getURI()));
                if (manifestElement != null) {
                    try {
                        Manifest manifest = DSSXMLUtils.initManifest(manifestElement);
                        List<Reference> manifestReferences = DSSXMLUtils.extractReferences(manifest);
                        Reference matchingReference = getMatchingReference(id, manifestReferences, signatureElement);
                        if (matchingReference != null) {
                            return matchingReference;
                        }
                    } catch (XMLSecurityException e) {
                        LOG.debug("Unable to instantiate the Manifest : {}", e.getMessage(), e);
                    }
                }
            }
        }
        return null;
    }

    private boolean isDataObjectFormatValuesCompliant(Element dataObjectFormat, Reference reference, Element signatureElement, XAdESPath xadesPaths) {
        Element dataObjectFormatMimeType = DomUtils.getElement(dataObjectFormat, xadesPaths.getCurrentMimeType());
        if (dataObjectFormatMimeType != null) {
            Element object = DSSXMLUtils.getObjectById(signatureElement, reference.getURI());
            if (object != null) {
                String objectMimeType = object.getAttribute(XMLDSigAttribute.MIME_TYPE.getAttributeName());
                if (Utils.isStringNotEmpty(objectMimeType) && !objectMimeType.equals(dataObjectFormatMimeType.getTextContent())) {
                    LOG.warn("DataObjectFormat's MimeType attribute shall have the same value as the corresponding signed ds:Object element, when present!");
                    return false;
                }
            }
        }
        Element dataObjectFormatEncoding = DomUtils.getElement(dataObjectFormat, xadesPaths.getCurrentEncoding());
        if (dataObjectFormatEncoding != null) {
            Element object = DSSXMLUtils.getObjectById(signatureElement, reference.getURI());
            if (object != null) {
                String objectEncoding = object.getAttribute(XMLDSigAttribute.ENCODING.getAttributeName());
                if (Utils.isStringNotEmpty(objectEncoding) && !objectEncoding.equals(dataObjectFormatEncoding.getTextContent())) {
                    LOG.warn("DataObjectFormat's Encoding attribute shall have the same value as the corresponding signed ds:Object element, when present!");
                    return false;
                }
            }
        }
        return true;
    }

    private boolean isValidXAdESBaselineDataObjectFormat(Element dataObjectFormat, XAdESSignature signature, XAdESPath xadesPaths) {
        if (!isValidXAdESDataObjectFormat(dataObjectFormat, signature, xadesPaths)) {
            return false;
        }
        // DataObjectFormat/Description (Cardinality 0 or 1)
        if (getNumberOfOccurrences(dataObjectFormat, xadesPaths.getCurrentDescription()) > 1) {
            LOG.warn("Only one DataObjectFormat/Description may be present for XAdES-BASELINE-B signature (cardinality 0 or 1)!");
            return false;
        }
        // DataObjectFormat/ObjectIdentifier (Cardinality 0 or 1)
        if (getNumberOfOccurrences(dataObjectFormat, xadesPaths.getCurrentObjectIdentifier()) > 1) {
            LOG.warn("Only one DataObjectFormat/ObjectIdentifier may be present for XAdES-BASELINE-B signature (cardinality 0 or 1)!");
            return false;
        }
        // DataObjectFormat/MimeType (Cardinality == 1)
        if (getNumberOfOccurrences(dataObjectFormat, xadesPaths.getCurrentMimeType()) != 1) {
            LOG.warn("DataObjectFormat/MimeType shall be present for XAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // DataObjectFormat/Encoding (Cardinality 0 or 1)
        if (getNumberOfOccurrences(dataObjectFormat, xadesPaths.getCurrentEncoding()) > 1) {
            LOG.warn("Only one DataObjectFormat/Encoding may be present for XAdES-BASELINE-B signature (cardinality 0 or 1)!");
            return false;
        }
        return true;
    }

    private boolean isSigningCertificateSignedInKeyInfo() {
        CertificateToken signingCertificate = signature.getSigningCertificateToken();
        if (signingCertificate != null && XAdESSignatureUtils.isKeyInfoCovered(signature)) {
            XAdESCertificateSource certificateSource = (XAdESCertificateSource) signature.getCertificateSource();
            List<CertificateToken> keyInfoCertificates = certificateSource.getKeyInfoCertificates();
            for (CertificateToken keyInfoCertificate : keyInfoCertificates) {
                if (signingCertificate.equals(keyInfoCertificate)) {
                    return true;
                }
            }
        }
        return false;
    }

    private int getNumberOfOccurrences(Element element, String xPath) {
        if (element != null && Utils.isStringNotEmpty(xPath)) {
            return DomUtils.getNodesAmount(element, xPath);
        }
        return 0;
    }

    private boolean isElementPresent(final Node xmlNode, final String xPathString) {
        if (Utils.isStringEmpty(xPathString)) {
            return false;
        }
        return DomUtils.isNotEmpty(xmlNode, xPathString);
    }

}
