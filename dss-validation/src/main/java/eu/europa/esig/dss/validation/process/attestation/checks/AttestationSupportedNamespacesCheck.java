package eu.europa.esig.dss.validation.process.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class verifies whether the attestation contains only claims within namespaces which are supported
 *
 */
public class AttestationSupportedNamespacesCheck extends AbstractMultiValuesCheckItem<XmlSAV> {

    /** attestation to check */
    private final AttestationWrapper attestation;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param attestation {@link AttestationWrapper}
     * @param constraint {@link MultiValuesRule}
     */
    public AttestationSupportedNamespacesCheck(I18nProvider i18nProvider, XmlSAV result,
                                               AttestationWrapper attestation, MultiValuesRule constraint) {
        super(i18nProvider, result, constraint);
        this.attestation = attestation;
    }

    @Override
    protected boolean process() {
        Set<String> claimNamespaces = attestation.getAllClaimNamespaces();
        if (Utils.isCollectionEmpty(claimNamespaces)) {
            return true;
        }
        return processAllValuesCheck(claimNamespaces);
    }

    @Override
    protected String buildAdditionalInfo() {
        Set<String> claimNamespaces = attestation.getAllClaimNamespaces();
        List<String> unsupportedNamespaces = claimNamespaces.stream().filter(c -> !processValueCheck(c)).collect(Collectors.toList());
        return i18nProvider.getMessage(MessageTag.EAA_UNSUPPORTED_CLAIM_NAMESPACES, Utils.joinStrings(unsupportedNamespaces, ", "));
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.ATTESTATION_CONSTRAINTS_FAILURE;
    }

}