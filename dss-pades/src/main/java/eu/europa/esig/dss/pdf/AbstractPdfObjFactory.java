package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.signature.resources.DSSResourcesHandlerBuilder;

/**
 * An abstract implementation of IPdfObjFactory allowing to set the configuration options
 *
 */
public abstract class AbstractPdfObjFactory implements IPdfObjFactory {

    /**
     * This object is used to create data container objects such as an OutputStream or a DSSDocument
     */
    private DSSResourcesHandlerBuilder resourcesHandlerBuilder;

    @Override
    public void setDSSResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
        this.resourcesHandlerBuilder = resourcesHandlerBuilder;
    }

    /**
     * This method is used to provide configuration to the given {@code pdfSignatureService}
     * (e.g. set the resources handler builder).
     *
     * @param pdfSignatureService {@link PDFSignatureService} to configure
     * @return {@link PDFSignatureService} configured
     */
    protected PDFSignatureService configure(PDFSignatureService pdfSignatureService) {
        if (resourcesHandlerBuilder != null) {
            pdfSignatureService.setResourcesHandlerBuilder(resourcesHandlerBuilder);
        }
        return pdfSignatureService;
    }

}
