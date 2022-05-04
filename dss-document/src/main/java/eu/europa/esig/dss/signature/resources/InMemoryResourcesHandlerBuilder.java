package eu.europa.esig.dss.signature.resources;

/**
 * This class creates an {@code InMemoryResourcesHandler} to create in-memory objects
 *
 * NOTE: This implementation is used by default
 */
public class InMemoryResourcesHandlerBuilder implements DSSResourcesHandlerBuilder {

    @Override
    public InMemoryResourcesHandler createResourcesHandler() {
        return new InMemoryResourcesHandler();
    }

}
