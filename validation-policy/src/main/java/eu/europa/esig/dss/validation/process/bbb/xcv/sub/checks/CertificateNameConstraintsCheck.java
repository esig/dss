package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
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
        Set<Map<String, String>> permittedSubtrees = null;
        /*
         * (c) excluded_subtrees:  a set of root names for each name type
         * (e.g., X.500 distinguished names, email addresses, or IP
         * addresses) defining a set of subtrees within which no subject
         * name in subsequent certificates in the certification path may
         * fall. This variable includes a set for each name type, and
         * the initial value is initial-excluded-subtrees.
         */
        Set<Map<String, String>> excludedSubtrees = null;

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
                final Map<String, String> certDN = toDNMap(cert.getCertificateDN());
                final List<Map<String, String>> subAltNames = cert.getSubjectAlternativeNames().stream()
                        .map(this::toDNMap).collect(Collectors.toList());

                if (permittedSubtrees != null) {
                    if (!isWithinDNSubtrees(certDN, permittedSubtrees)) {
                        return false;
                    }
                    for (Map<String, String> subAltName : subAltNames) {
                        if (!isWithinDNSubtrees(subAltName, permittedSubtrees)) {
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
                    if (isWithinDNSubtrees(certDN, excludedSubtrees)) {
                        return false;
                    }
                    for (Map<String, String> subAltName : subAltNames) {
                        if (isWithinDNSubtrees(subAltName, excludedSubtrees)) {
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
            final Set<Map<String, String>> certPermittedSubtrees = toGeneralSubtreeMapSet(cert.getPermittedSubtrees());
            final Set<Map<String, String>> certExcludedSubtrees = toGeneralSubtreeMapSet(cert.getExcludedSubtrees());
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
                    permittedSubtrees = intersect(permittedSubtrees, certPermittedSubtrees);
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
                    excludedSubtrees = union(excludedSubtrees, certExcludedSubtrees);
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

    private boolean isWithinDNSubtrees(Map<String, String> certDN, Set<Map<String, String>> permittedSubtrees) {
        for (Map<String, String> permittedSubtree : permittedSubtrees) {
            if (isWithinDNSubtree(certDN, permittedSubtree)) {
                return true;
            }
        }
        return false;
    }

    private Set<Map<String, String>> toGeneralSubtreeMapSet(List<XmlGeneralSubtree> generalSubtrees) {
        Set<Map<String, String>> result = new HashSet<>();
        for (XmlGeneralSubtree xmlGeneralSubtree : generalSubtrees) {
            if (GeneralNameType.DIRECTORY_NAME == xmlGeneralSubtree.getType()) {
                Map<String, String> dnMap = toDNMap(xmlGeneralSubtree.getValue());
                if (Utils.isMapNotEmpty(dnMap)) {
                    result.add(dnMap);
                } else {
                    LOG.warn("Unable to build a DN map for general subtree with value '{}'", xmlGeneralSubtree.getValue());
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("The general name type '{}' is not supported and skipped!", xmlGeneralSubtree.getType().getLabel());
                }
            }
        }
        return result;
    }

    private Set<Map<String, String>> intersect(Set<Map<String, String>> originalSet, Set<Map<String, String>> currentSet) {
        final Set<Map<String, String>> result = new HashSet<>();
        for (Map<String, String> currentMap : currentSet) {
            for (Map<String, String> originalMap : originalSet) {
                if (isWithinDNSubtree(originalMap, currentMap)) {
                    result.add(currentMap);
                } else if (isWithinDNSubtree(currentMap, originalMap)) {
                    result.add(originalMap);
                }
            }
            if (originalSet.contains(currentMap)) {
                result.add(currentMap);
            }
        }
        return result;
    }

    private boolean isWithinDNSubtree(Map<String, String> dn, Map<String, String> subtree) {
        if (subtree.size() < 1) {
            return false;
        }
        if (subtree.size() > dn.size()) {
            return false;
        }
        for (Map.Entry<String, String> entry : subtree.entrySet()) {
            String subtreeKey = entry.getKey();
            String subtreeValue = entry.getValue();
            if (!dn.containsKey(subtreeKey) || !subtreeValue.equals(dn.get(subtreeKey))) {
                return false;
            }
        }
        return true;
    }

    private Set<Map<String, String>> union(Set<Map<String, String>> originalSet, Set<Map<String, String>> currentSet) {
        final Set<Map<String, String>> result = new HashSet<>();
        for (Map<String, String> currentMap : currentSet) {
            for (Map<String, String> originalMap : originalSet) {
                if (isWithinDNSubtree(originalMap, currentMap)) {
                    result.add(currentMap);
                } else if (isWithinDNSubtree(currentMap, originalMap)) {
                    result.add(originalMap);
                } else {
                    result.add(currentMap);
                    result.add(originalMap);
                }
            }
            if (originalSet.contains(currentMap)) {
                result.add(currentMap);
            }
        }
        return result;
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
