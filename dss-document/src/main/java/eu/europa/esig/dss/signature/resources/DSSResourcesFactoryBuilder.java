package eu.europa.esig.dss.signature.resources;

/**
 * This class builds a new instance of {@code DSSResourcesFactory}
 *
 */
public interface DSSResourcesFactoryBuilder<F extends DSSResourcesFactory> {

    /**
     * This method instantiates the corresponding factory.
     *
     * @return factory {@link DSSResourcesFactory}
     */
   F instantiateFactory();

}
