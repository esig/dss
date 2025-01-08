package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.enumerations.SignatureLevel;

class XAdESExtensionLTToLTTest extends AbstractXAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LT;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LT;
    }

}
