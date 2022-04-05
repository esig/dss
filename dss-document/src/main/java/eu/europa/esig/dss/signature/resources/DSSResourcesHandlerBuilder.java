package eu.europa.esig.dss.signature.resources;

/**
 * This class builds a new instance of {@code DSSResourcesHandler}
 *
 */
public interface DSSResourcesHandlerBuilder<R extends DSSResourcesHandler> {

    /**
     * This method instantiates the corresponding factory.
     *
     * @return factory {@link DSSResourcesHandler}
     */
   R createResourcesHandler();

}
