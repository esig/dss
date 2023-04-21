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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralSubtree;
import eu.europa.esig.dss.enumerations.GeneralNameType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This check verifies the validity of the certificate in regard to "Name constraint"
 * certificate extension's value in its certificate chain.
 * NOTE: only directoryName general name type is supported by this class.
 *
 */
public class CertificateNameConstraintsCheck extends ChainItem<XmlSubXCV> {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateNameConstraintsCheck.class);


    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public CertificateNameConstraintsCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                                      LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        /*
         * 6.1.2. Initialization
         */
        final List<CertificateWrapper> certificateChain = new ArrayList<>();
        certificateChain.add(certificate);
        certificateChain.addAll(certificate.getCertificateChain()); // current certificate is not returned
        /*
         * (b) permitted_subtrees:  a set of root names for each name type
         * (e.g., X.500 distinguished names, email addresses, or IP
         * addresses) defining a set of subtrees within which all
         * subject names in subsequent certificates in the certification
         * path MUST fall. This variable includes a set for each name
         * type, and the initial value is initial-permitted-subtrees.
         */
        Set<XmlGeneralName> permittedSubtrees = null;
        /*
         * (c) excluded_subtrees:  a set of root names for each name type
         * (e.g., X.500 distinguished names, email addresses, or IP
         * addresses) defining a set of subtrees within which no subject
         * name in subsequent certificates in the certification path may
         * fall. This variable includes a set for each name type, and
         * the initial value is initial-excluded-subtrees.
         */
        Set<XmlGeneralName> excludedSubtrees = null;

        /*
         * 6.1.3. Basic Certificate Processing
         * The basic path processing actions to be performed for certificate i
         * (for all i in [1..n]) are listed below.
         */
        for (int i = certificateChain.size() - 1; i > -1; i--) {
            final CertificateWrapper cert = certificateChain.get(i);
            /*
             * (b) If certificate i is self-issued and it is not the final
             * certificate in the path, skip this step for certificate i.
             * Otherwise, verify that the subject name is within one of the
             * permitted_subtrees for X.500 distinguished names, and verify
             * that each of the alternative names in the subjectAltName
             * extension (critical or non-critical) is within one of the
             * permitted_subtrees for that name type.
             */
            // perform validation only for the current certificate to support flexible validation policy
            if (i == 0) {
                final String certDN = cert.getCertificateDN();
                final List<XmlGeneralName> subAltNames = cert.getSubjectAlternativeNames();

                if (permittedSubtrees != null) {
                    Set<XmlGeneralName> dnGeneralNames = getSubtreesOfType(permittedSubtrees, GeneralNameType.DIRECTORY_NAME);
                    if (Utils.isCollectionNotEmpty(dnGeneralNames) && !isWithinDNSubtrees(certDN, dnGeneralNames)) {
                        return false;
                    }
                    for (XmlGeneralName subAltName : subAltNames) {
                        Set<XmlGeneralName> subtreesOfType = getSubtreesOfType(permittedSubtrees, subAltName.getType());
                        if (Utils.isCollectionNotEmpty(subtreesOfType) && !isWithinSubtrees(subAltName, subtreesOfType)) {
                            return false;
                        }
                    }
                }
                /*
                 * (c) If certificate i is self-issued and it is not the final
                 * certificate in the path, skip this step for certificate i.
                 * Otherwise, verify that the subject name is not within any of
                 * the excluded_subtrees for X.500 distinguished names, and
                 * verify that each of the alternative names in the
                 * subjectAltName extension (critical or non-critical) is not
                 * within any of the excluded_subtrees for that name type.
                 */
                if (excludedSubtrees != null) {
                    Set<XmlGeneralName> dnGeneralNames = getSubtreesOfType(excludedSubtrees, GeneralNameType.DIRECTORY_NAME);
                    if (Utils.isCollectionNotEmpty(dnGeneralNames) && isWithinDNSubtrees(certDN, excludedSubtrees)) {
                        return false;
                    }
                    for (XmlGeneralName subAltName : subAltNames) {
                        Set<XmlGeneralName> subtreesOfType = getSubtreesOfType(excludedSubtrees, subAltName.getType());
                        if (Utils.isCollectionNotEmpty(subtreesOfType) && isWithinSubtrees(subAltName, excludedSubtrees)) {
                            return false;
                        }
                    }
                }
            }
            /*
             * 6.1.4. Preparation for Certificate i+1
             *
             * (g) If a name constraints extension is included in the
             * certificate, modify the permitted_subtrees and
             * excluded_subtrees state variables as follows:
             */
            final Set<XmlGeneralName> certPermittedSubtrees = toXmlGeneralNameSet(cert.getPermittedSubtrees());
            final Set<XmlGeneralName> certExcludedSubtrees = toXmlGeneralNameSet(cert.getExcludedSubtrees());
            /*
             * (1) If permittedSubtrees is present in the certificate, set
             * the permitted_subtrees state variable to the intersection
             * of its previous value and the value indicated in the
             * extension field. If permittedSubtrees does not include a
             * particular name type, the permitted_subtrees state
             * variable is unchanged for that name type. For example,
             * the intersection of example.com and foo.example.com is
             * foo.example.com. And the intersection of example.com and
             * example.net is the empty set.
             */
            if (Utils.isCollectionNotEmpty(certPermittedSubtrees)) {
                if (permittedSubtrees != null) {
                    permittedSubtrees = intersectNew(permittedSubtrees, certPermittedSubtrees);
                } else {
                    permittedSubtrees = certPermittedSubtrees;
                }
            }

            /* (2) If excludedSubtrees is present in the certificate, set the
             * excluded_subtrees state variable to the union of its
             * previous value and the value indicated in the extension
             * field. If excludedSubtrees does not include a particular
             * name type, the excluded_subtrees state variable is
             * unchanged for that name type. For example, the union of
             * the name spaces example.com and foo.example.com is
             * example.com.  And the union of example.com and example.net
             * is both name spaces.
             */
            if (Utils.isCollectionNotEmpty(certExcludedSubtrees)) {
                if (excludedSubtrees != null) {
                    excludedSubtrees = unionNew(excludedSubtrees, certExcludedSubtrees);
                } else {
                    excludedSubtrees = certExcludedSubtrees;
                }
            }
        }

        return true;
    }

    /**
     * This method builds a DN map based on RFC 2253 encoded string
     * NOTE: see {@code sun.security.x509.X500Name.parseRFC2253DN(String dnString)}
     *
     * @param rfc2253EncodedString {@link String} to parse
     * @return map
     */
    private Map<String, String> toDNMap(String rfc2253EncodedString) {
        if (Utils.isStringEmpty(rfc2253EncodedString)) {
            return Collections.emptyMap();
        }
        final Map<String, String> result = new HashMap<>();
        String nextStr;
        Map.Entry<String, String> rdn;
        int nextEnd = rfc2253EncodedString.indexOf(',');
        int searchOffset = 0;
        int dnOffset = 0;
        while (nextEnd >= 0) {
            if (nextEnd > 0 && rfc2253EncodedString.charAt(nextEnd - 1) != '\\') {
                nextStr = rfc2253EncodedString.substring(dnOffset, nextEnd);
                rdn = getRDN(nextStr);
                if (rdn != null) {
                    result.put(rdn.getKey(), rdn.getValue());
                }
                dnOffset = nextEnd + 1;
            }
            searchOffset = nextEnd + 1;
            nextEnd = rfc2253EncodedString.indexOf(',', searchOffset);
        }
        // get last value entry
        String substring = rfc2253EncodedString.substring(dnOffset);
        rdn = getRDN(substring);
        if (rdn != null) {
            result.put(rdn.getKey(), rdn.getValue());
        }
        return result;
    }

    private Map.Entry<String, String> getRDN(String str) {
        int nextEquals = str.indexOf('=');
        if (nextEquals >= 0 && str.length() >= nextEquals + 1) {
            return new AbstractMap.SimpleEntry<>(str.substring(0, nextEquals), str.substring(nextEquals + 1));
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Unable to build an RDN for string '{}'! Not a DN.", str);
        }
        return null;
    }

    private Set<XmlGeneralName> getSubtreesOfType(Set<XmlGeneralName> subtrees, GeneralNameType generalNameType) {
        return subtrees.stream().filter(n -> generalNameType.equals(n.getType())).collect(Collectors.toSet());
    }

    private boolean isWithinSubtrees(XmlGeneralName generalName, Set<XmlGeneralName> permittedSubtrees) {
        for (XmlGeneralName permittedSubtree : permittedSubtrees) {
            if (isWithinSubtree(generalName, permittedSubtree)) {
                return true;
            }
        }
        return false;
    }

    private boolean isWithinDNSubtrees(String certDN, Set<XmlGeneralName> permittedSubtrees) {
        for (XmlGeneralName permittedSubtree : permittedSubtrees) {
            if (isWithinDNSubtree(certDN, permittedSubtree.getValue())) {
                return true;
            }
        }
        return false;
    }

    private Set<XmlGeneralName> toXmlGeneralNameSet(Collection<XmlGeneralSubtree> generalSubtrees) {
        if (Utils.isCollectionEmpty(generalSubtrees)) {
            return Collections.emptySet();
        }
        return generalSubtrees.stream().map(n -> (XmlGeneralName) n).collect(Collectors.toSet());
    }

    private Set<XmlGeneralName> intersectNew(Collection<XmlGeneralName> originalSet, Collection<XmlGeneralName> currentSet) {
        final Set<XmlGeneralName> result = new HashSet<>();
        for (XmlGeneralName currentGeneralName : currentSet) {
            boolean predecessorFound = false;
            for (XmlGeneralName originalGeneralName : originalSet) {
                if (currentGeneralName.getType().equals(originalGeneralName.getType())) {
                    if (isWithinSubtree(originalGeneralName, currentGeneralName)) {
                        result.add(currentGeneralName);
                    } else if (isWithinSubtree(currentGeneralName, originalGeneralName)) {
                        result.add(originalGeneralName);
                    }
                }
            }
            if (!predecessorFound) {
                result.add(currentGeneralName);
            }
        }
        return result;
    }

    private Set<XmlGeneralName> unionNew(Collection<XmlGeneralName> originalSet, Collection<XmlGeneralName> currentSet) {
        final Set<XmlGeneralName> result = new HashSet<>();
        for (XmlGeneralName currentGeneralName : currentSet) {
            if (Utils.isCollectionNotEmpty(originalSet)) {
                for (XmlGeneralName originalGeneralName : originalSet) {
                    if (isWithinSubtree(originalGeneralName, currentGeneralName)) {
                        result.add(currentGeneralName);
                    } else if (isWithinSubtree(currentGeneralName, originalGeneralName)) {
                        result.add(originalGeneralName);
                    } else {
                        result.add(currentGeneralName);
                        result.add(originalGeneralName);
                    }
                }
            } else {
                result.add(currentGeneralName);
            }
        }
        return result;
    }

    private boolean isWithinSubtree(XmlGeneralName generalName, XmlGeneralName subtreeGeneralName) {
        if (Utils.isStringEmpty(generalName.getValue()) || Utils.isStringEmpty(subtreeGeneralName.getValue())) {
            return false;
        }
        if (subtreeGeneralName.getValue().length() > generalName.getValue().length()) {
            return false;
        }

        switch (generalName.getType()) {
            case UNIFORM_RESOURCE_IDENTIFIER:
                return isWithinURISubtree(generalName.getValue(), subtreeGeneralName.getValue());
            case RFC822_NAME:
                return isWithinEmailSubtree(generalName.getValue(), subtreeGeneralName.getValue());
            case DNS_NAME:
                return isWithinDNSSubtree(generalName.getValue(), subtreeGeneralName.getValue());
            case DIRECTORY_NAME:
                return isWithinDNSubtree(generalName.getValue(), subtreeGeneralName.getValue());
            case IP_ADDRESS:
            case OTHER_NAME:
            case X400_ADDRESS:
            case EDI_PARTY_NAME:
            case REGISTERED_ID:
                LOG.warn("The NameConstraint of type '{}' is not supported. Full comparison is executed.", generalName.getType());
                return isWithinOtherNameSubtree(generalName.getValue(), subtreeGeneralName.getValue());
        }
        return false;
    }

    private boolean isWithinURISubtree(String value, String subtree) {
        if (subtree.startsWith(".")) {
            return value.toLowerCase().endsWith(subtree.toLowerCase());
        }
        return subtree.equalsIgnoreCase(value);
    }

    private boolean isWithinEmailSubtree(String value, String subtree) {
        if (subtree.indexOf('@') != -1) {
            return value.equalsIgnoreCase(subtree);
        }
        return value.toLowerCase().endsWith(subtree.toLowerCase());
    }

    private boolean isWithinDNSSubtree(String value, String subtree) {
        return value.toLowerCase().endsWith(subtree.toLowerCase());
    }

    private boolean isWithinDNSubtree(String value, String subtree) {
        Map<String, String> dnMap = toDNMap(value);
        Map<String, String> subtreeMap = toDNMap(subtree);
        for (Map.Entry<String, String> entry : subtreeMap.entrySet()) {
            String subtreeKey = entry.getKey();
            String subtreeValue = entry.getValue();
            if (!dnMap.containsKey(subtreeKey) || !subtreeValue.equals(dnMap.get(subtreeKey))) {
                return false;
            }
        }
        return true;
    }

    private boolean isWithinOtherNameSubtree(String value, String subtree) {
        return subtree.equals(value);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_DCSBSINC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_DCSBSINC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE;
    }

}
