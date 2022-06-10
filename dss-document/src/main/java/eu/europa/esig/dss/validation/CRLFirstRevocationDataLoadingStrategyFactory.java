package eu.europa.esig.dss.validation;

/**
 * This class initializes a {@code CRLFirstRevocationDataLoadingStrategy}.
 *
 */
public class CRLFirstRevocationDataLoadingStrategyFactory implements RevocationDataLoadingStrategyFactory {

    @Override
    public RevocationDataLoadingStrategy create() {
        return new CRLFirstRevocationDataLoadingStrategy();
    }

}
