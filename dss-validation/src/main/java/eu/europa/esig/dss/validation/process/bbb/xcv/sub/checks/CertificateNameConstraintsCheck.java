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
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
     * @param constraint {@link LevelRule}
     */
    public CertificateNameConstraintsCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                                      LevelRule constraint) {
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
        Map<GeneralNameType, Set<XmlGeneralName>> permittedSubtrees = null;
        /*
         * (c) excluded_subtrees:  a set of root names for each name type
         * (e.g., X.500 distinguished names, email addresses, or IP
         * addresses) defining a set of subtrees within which no subject
         * name in subsequent certificates in the certification path may
         * fall. This variable includes a set for each name type, and
         * the initial value is initial-excluded-subtrees.
         */
        Map<GeneralNameType, Set<XmlGeneralName>> excludedSubtrees = null;

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
                /*
                 * Legacy implementations exist where an electronic mail address is
                 * embedded in the subject distinguished name in an attribute of type
                 * emailAddress (Section 4.1.2.6). When constraints are imposed on the
                 * alternative name, the rfc822Name constraint MUST be applied to the
                 * attribute of type emailAddress in the subject distinguished name.
                 */
                if (!containsRFC822SubjectAlternativeName(subAltNames)) {
                    subAltNames.addAll(getEmailAddressDNIfPresent(certDN));
                }

                if (permittedSubtrees != null) {
                    Set<XmlGeneralName> dnGeneralNames = permittedSubtrees.get(GeneralNameType.DIRECTORY_NAME);
                    if (dnGeneralNames != null && !isWithinDNSubtrees(certDN, dnGeneralNames)) {
                        return false;
                    }
                    for (XmlGeneralName subAltName : subAltNames) {
                        Set<XmlGeneralName> subtreesOfType = permittedSubtrees.get(subAltName.getType());
                        if (subtreesOfType != null && !isWithinSubtrees(subAltName, subtreesOfType)) {
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
                    Set<XmlGeneralName> dnGeneralNames = excludedSubtrees.get(GeneralNameType.DIRECTORY_NAME);
                    if (dnGeneralNames != null && isWithinDNSubtrees(certDN, dnGeneralNames)) {
                        return false;
                    }
                    for (XmlGeneralName subAltName : subAltNames) {
                        Set<XmlGeneralName> subtreesOfType = excludedSubtrees.get(subAltName.getType());
                        if (subtreesOfType != null && isWithinSubtrees(subAltName, subtreesOfType)) {
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
            final Map<GeneralNameType, Set<XmlGeneralName>> certPermittedSubtrees = toXmlGeneralNameMap(cert.getPermittedSubtrees());
            final Map<GeneralNameType, Set<XmlGeneralName>> certExcludedSubtrees = toXmlGeneralNameMap(cert.getExcludedSubtrees());
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
            if (certPermittedSubtrees != null) {
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
            if (certExcludedSubtrees != null) {
                if (excludedSubtrees != null) {
                    excludedSubtrees = unionNew(excludedSubtrees, certExcludedSubtrees);
                } else {
                    excludedSubtrees = certExcludedSubtrees;
                }
            }
        }

        return true;
    }

    private boolean containsRFC822SubjectAlternativeName(List<XmlGeneralName> subAltNames) {
        return Utils.isCollectionNotEmpty(subAltNames) && 
                subAltNames.stream().anyMatch(n -> GeneralNameType.RFC822_NAME.equals(n.getType()));
    }
    
    private Set<XmlGeneralName> getEmailAddressDNIfPresent(String certDN) {
        Map<String, Set<String>> dnMap = toDNMap(certDN);
        Set<String> emailAddressValues = dnMap.get("1.2.840.113549.1.9.1"); // emailAddress

        Set<XmlGeneralName> result = new HashSet<>();
        if (emailAddressValues != null) {
            for (String emailAddress : emailAddressValues) {
                XmlGeneralName xmlGeneralName = new XmlGeneralName();
                xmlGeneralName.setType(GeneralNameType.RFC822_NAME);
                xmlGeneralName.setValue(emailAddress);
                result.add(xmlGeneralName);
            }
        }
        return result;
    }

    /**
     * This method builds a DN map based on RFC 2253 encoded string
     * NOTE: see {@code sun.security.x509.X500Name.parseRFC2253DN(String dnString)}
     *
     * @param rfc2253EncodedString {@link String} to parse
     * @return map
     */
    private Map<String, Set<String>> toDNMap(String rfc2253EncodedString) {
        if (Utils.isStringEmpty(rfc2253EncodedString)) {
            return Collections.emptyMap();
        }
        final Map<String, Set<String>> result = new HashMap<>();
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
                    enrichMap(result, rdn.getKey(), rdn.getValue());
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
            enrichMap(result, rdn.getKey(), rdn.getValue());
        }
        return result;
    }

    private void enrichMap(Map<String, Set<String>> dnMap, String rdnKey, String rdnValue) {
        Set<String> values = dnMap.computeIfAbsent(rdnKey, k -> new HashSet<>());
        values.add(rdnValue);
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

    private boolean isWithinSubtrees(XmlGeneralName generalName, Set<XmlGeneralName> permittedSubtrees) {
        for (XmlGeneralName permittedSubtree : permittedSubtrees) {
            if (isWithinSubtree(generalName, permittedSubtree)) {
                return true;
            }
        }
        return false;
    }

    private boolean isWithinDNSubtrees(String certDN, Set<XmlGeneralName> permittedSubtrees) {
        if (Utils.isStringEmpty(certDN) && Utils.isCollectionEmpty(permittedSubtrees)) {
            return true;
        }
        for (XmlGeneralName permittedSubtree : permittedSubtrees) {
            if (isWithinDNSubtree(certDN, permittedSubtree.getValue())) {
                return true;
            }
        }
        return false;
    }

    private Map<GeneralNameType, Set<XmlGeneralName>> toXmlGeneralNameMap(Collection<XmlGeneralSubtree> generalSubtrees) {
        if (Utils.isCollectionEmpty(generalSubtrees)) {
            return null;
        }
        Map<GeneralNameType, Set<XmlGeneralName>> result = new EnumMap<>(GeneralNameType.class);
        for (XmlGeneralSubtree generalSubtree : generalSubtrees) {
            Set<XmlGeneralName> values = result.computeIfAbsent(generalSubtree.getType(), k -> new HashSet<>());
            values.add(generalSubtree);
        }
        return result;
    }

    private Map<GeneralNameType, Set<XmlGeneralName>> intersectNew(Map<GeneralNameType, Set<XmlGeneralName>> originalConstraints,
                                                                   Map<GeneralNameType, Set<XmlGeneralName>> currentConstraints) {
        Map<GeneralNameType, Set<XmlGeneralName>> result = new EnumMap<>(GeneralNameType.class);
        for (Map.Entry<GeneralNameType, Set<XmlGeneralName>> currentEntry : currentConstraints.entrySet()) {
            final GeneralNameType type = currentEntry.getKey();
            final Set<XmlGeneralName> currentGeneralNames = currentEntry.getValue();
            final Set<XmlGeneralName> intersection = result.computeIfAbsent(type, k -> new HashSet<>());

            Set<XmlGeneralName> originalSubtrees = originalConstraints.get(type);
            if (Utils.isCollectionNotEmpty(originalSubtrees)) {
                for (XmlGeneralName currentGeneralName : currentGeneralNames) {
                    for (XmlGeneralName originalGeneralName : originalSubtrees) {
                        if (isWithinSubtree(originalGeneralName, currentGeneralName)) {
                            intersection.add(originalGeneralName);
                        } else if (isWithinSubtree(currentGeneralName, originalGeneralName)) {
                            intersection.add(currentGeneralName);
                        }
                    }
                }
            } else {
                intersection.addAll(currentGeneralNames);
            }
        }

        for (Map.Entry<GeneralNameType, Set<XmlGeneralName>> originalEntry : originalConstraints.entrySet()) {
            if (!result.containsKey(originalEntry.getKey())) {
                final Set<XmlGeneralName> intersection = result.computeIfAbsent(originalEntry.getKey(), k -> new HashSet<>());
                intersection.addAll(originalEntry.getValue());
            }
        }

        return result;
    }

    private Map<GeneralNameType, Set<XmlGeneralName>> unionNew(Map<GeneralNameType, Set<XmlGeneralName>> originalConstraints, Map<GeneralNameType, Set<XmlGeneralName>> currentConstraints) {
        Map<GeneralNameType, Set<XmlGeneralName>> result = new EnumMap<>(GeneralNameType.class);
        for (Map.Entry<GeneralNameType, Set<XmlGeneralName>> currentEntry : currentConstraints.entrySet()) {
            final GeneralNameType type = currentEntry.getKey();
            final Set<XmlGeneralName> currentGeneralNames = currentEntry.getValue();
            final Set<XmlGeneralName> union = result.computeIfAbsent(type, k -> new HashSet<>());

            Set<XmlGeneralName> originalSubtrees = originalConstraints.get(type);
            if (Utils.isCollectionNotEmpty(originalSubtrees)) {
                for (XmlGeneralName currentGeneralName : currentGeneralNames) {
                    for (XmlGeneralName originalGeneralName : originalSubtrees) {
                        if (isWithinSubtree(originalGeneralName, currentGeneralName)) {
                            union.add(currentGeneralName);
                        } else if (isWithinSubtree(currentGeneralName, originalGeneralName)) {
                            union.add(originalGeneralName);
                        } else {
                            union.add(currentGeneralName);
                            union.add(originalGeneralName);
                        }
                    }
                }
            } else {
                union.addAll(currentGeneralNames);
            }
        }

        for (Map.Entry<GeneralNameType, Set<XmlGeneralName>> originalEntry : originalConstraints.entrySet()) {
            if (!result.containsKey(originalEntry.getKey())) {
                final Set<XmlGeneralName> union = result.computeIfAbsent(originalEntry.getKey(), k -> new HashSet<>());
                union.addAll(originalEntry.getValue());
            }
        }

        return result;
    }

    private boolean isWithinSubtree(XmlGeneralName generalName, XmlGeneralName subtreeGeneralName) {
        if (Utils.isStringEmpty(generalName.getValue()) || Utils.isStringEmpty(subtreeGeneralName.getValue())) {
            return false;
        }
        if (!GeneralNameType.IP_ADDRESS.equals(generalName.getType()) &&
                subtreeGeneralName.getValue().length() > generalName.getValue().length()) {
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
                return isWithinIPAddressSubtree(generalName.getValue(), subtreeGeneralName.getValue());
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
        String domainNameSubtree = ValidationProcessUtils.getDomainName(subtree);
        String domainNameValue = ValidationProcessUtils.getDomainName(value);
        return isWithinDomain(domainNameValue, domainNameSubtree);
    }

    private boolean isWithinDomain(String value, String domain) {
        if (domain.startsWith(".")) {
            return value.toLowerCase().endsWith(domain.toLowerCase());
        }
        return domain.equalsIgnoreCase(value);
    }

    private boolean isWithinEmailSubtree(String value, String subtree) {
        if (isEmail(subtree)) {
            return value.equalsIgnoreCase(subtree);
        }
        if (isEmail(value)) {
            value = getDomainNameFromEmail(value);
        }
        return isWithinDomain(value, subtree);
    }

    private boolean isEmail(String str) {
        return str.indexOf('@') != -1;
    }

    private String getDomainNameFromEmail(String email) {
        return email.substring(email.indexOf('@') + 1);
    }

    private boolean isWithinDNSSubtree(String value, String subtree) {
        String[] valueArray = value.split("\\.");
        String[] subTreeArray = subtree.split("\\.");
        int diff = valueArray.length - subTreeArray.length;
        if (diff == 0) {
            return Arrays.equals(subTreeArray, valueArray);
        } else if (diff > 0) {
            for (int i = subTreeArray.length - 1; i > -1; i--) {
                if (!subTreeArray[i].equals(valueArray[i + diff])) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    private boolean isWithinDNSubtree(String value, String subtree) {
        Map<String, Set<String>> dnMap = toDNMap(value);
        Map<String, Set<String>> subtreeMap = toDNMap(subtree);
        for (Map.Entry<String, Set<String>> entry : subtreeMap.entrySet()) {
            String subtreeKey = entry.getKey();
            Set<String> subtreeValues = entry.getValue();
            if (!dnMap.containsKey(subtreeKey) || !dnMap.get(subtreeKey).containsAll(subtreeValues)) {
                return false;
            }
        }
        return true;
    }

    private boolean isWithinIPAddressSubtree(String value, String subtree) {
        byte[] ipAddress = toByteArrayIPAddress(value);
        byte[] constraint = toByteArrayIPAddress(subtree);

        int length = ipAddress.length;
        if (length != (constraint.length / 2)) {
            return false;
        }

        byte[] subnetMask = Utils.subarray(constraint, length, constraint.length);
        byte[] constraintSubnetAddress = new byte[length];
        byte[] ipSubnetAddress = new byte[length];

        // the resulting IP address by applying the subnet mask
        for (int i = 0; i < length; i++) {
            constraintSubnetAddress[i] = (byte)(constraint[i] & subnetMask[i]);
            ipSubnetAddress[i] = (byte)(ipAddress[i] & subnetMask[i]);
        }

        return Arrays.equals(constraintSubnetAddress, ipSubnetAddress);
    }

    private byte[] toByteArrayIPAddress(String ipAddress) {
        // consider internal hex-encoded values
        if (ipAddress.startsWith("#")) {
            ipAddress = ipAddress.replace("#", "");
            if (Utils.isHexEncoded(ipAddress)) {
                return Utils.fromHex(ipAddress);
            }
        }
        LOG.debug("Incorrectly encoded IP Address value: {}", ipAddress);
        return ipAddress.getBytes();
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
