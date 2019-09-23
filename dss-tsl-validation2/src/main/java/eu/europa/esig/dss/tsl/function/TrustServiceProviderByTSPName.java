package eu.europa.esig.dss.tsl.function;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

public class TrustServiceProviderByTSPName implements TrustServiceProviderPredicate{
    
    private String tspName;
    
    public TrustServiceProviderByTSPName(String tspName) {
        this.tspName = tspName;
    }
    
    @Override
    public boolean test(TSPType trustServiceProvider) {
        if(trustServiceProvider != null && Utils.isStringNotEmpty(tspName)) {
            TSPInformationType tspInformation = trustServiceProvider.getTSPInformation();
            InternationalNamesType tspName = tspInformation.getTSPName();
            List<MultiLangNormStringType> multiLangNames = tspName.getName();
            for(MultiLangNormStringType name: multiLangNames) {
                if (Utils.areStringsEqualIgnoreCase(this.tspName, name.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }
    
}