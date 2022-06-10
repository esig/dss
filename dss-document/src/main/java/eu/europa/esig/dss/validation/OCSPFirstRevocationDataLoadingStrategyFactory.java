package eu.europa.esig.dss.validation;

/**
 * This class initializes a {@code OCSPFirstRevocationDataLoadingStrategy}.
 *
 */
public class OCSPFirstRevocationDataLoadingStrategyFactory implements RevocationDataLoadingStrategyFactory {

    @Override
    public RevocationDataLoadingStrategy create() {
        return new OCSPFirstRevocationDataLoadingStrategy();
    }

}
